#!/bin/bash
# Rebuild website/media/ from the source screen recordings in website/Videos/.
# Only the outputs in media/ are needed to serve the site; Videos/ is the master.
#
# Two things here are NOT optional:
#   1. The sources are HEVC in a .mov container. Chrome and Firefox will not play
#      them. They must be transcoded to H.264/MP4.
#   2. The sources are HDR (BT.2020 primaries, PQ transfer, 10-bit). A plain
#      convert crushes them to washed-out grey — the emerald "MONITORING ACTIVE"
#      and the amber MEDIUM badges lose their colour entirely. The zscale ->
#      tonemap -> bt709 chain below is what keeps the brand colours intact.
#
# ffmpeg comes from the imageio-ffmpeg wheel (a self-contained static binary):
#   pip install imageio-ffmpeg
# macOS's built-in avconvert can do step 1 but has no bitrate/CRF control, and
# produced 15 MB for a 14s clip where CRF 26 produces 2 MB. Hence ffmpeg.
set -euo pipefail
cd "$(dirname "$0")"

FF=$(python3 -c "import imageio_ffmpeg as f;print(f.get_ffmpeg_exe())")
SRC=Videos
OUT=media
mkdir -p "$OUT"

TM="zscale=t=linear:npl=100,format=gbrpf32le,zscale=p=bt709,tonemap=tonemap=hable:desat=0,zscale=t=bt709:m=bt709:r=tv,format=yuv420p"
TOPCROP="crop=iw:ih-24:0:24"        # trims the desktop wallpaper strip above the app window
LISTCROP="crop=2300:1230:570:659"   # tight on the event stream (sources are 3006x1886)

enc () { # name src start duration crop width crf
  local name=$1 src=$2 ss=$3 dur=$4 crop=$5 w=$6 crf=$7
  "$FF" -y -ss "$ss" -t "$dur" -i "$SRC/$src" \
    -vf "$crop,$TM,scale=$w:-2:flags=lanczos,fps=30" \
    -c:v libx264 -preset slow -crf "$crf" -pix_fmt yuv420p -g 60 \
    -movflags +faststart -an "$OUT/$name.mp4" -loglevel error
  # first frame becomes the poster, so the page never flashes black
  "$FF" -y -i "$OUT/$name.mp4" -frames:v 1 -q:v 4 "$OUT/$name.jpg" -loglevel error
  printf "  %-14s %6s mp4  %5s poster\n" "$name" \
    "$(du -h "$OUT/$name.mp4"|cut -f1)" "$(du -h "$OUT/$name.jpg"|cut -f1)"
}

echo "building website/media:"
#   Dashboard.mov is two scenes in one take: the overview/event stream (0-5.4s),
#   then an event is clicked and the AI-explanation drawer opens (5.4-16.8s).
enc hero     "Dashboard.mov"          0    21.8 "$TOPCROP"  1600 30   # scrimmed bg, quality can be low
enc memory   "Dashboard.mov"         16.9   4.9 "$LISTCROP" 1200 26   # cropped to the event stream
enc incident "Dashboard.mov"          5.4  11.4 "$TOPCROP"  1500 26   # the drawer + AI explanation
enc brief    "Daily Brief.mov"        9.5  12.4 "$TOPCROP"  1500 26   # brief modal generating
enc report   "Report Generation.mov"  0.4  13.4 "$TOPCROP"  1500 26   # export -> PDF opens

# the one full-width static screenshot (its own section, no text over it)
"$FF" -y -ss 1.5 -i "$SRC/Dashboard.mov" -vf "$TOPCROP,$TM,scale=2400:-2:flags=lanczos" \
  -frames:v 1 -q:v 3 "$OUT/dashboard-full.jpg" -loglevel error
printf "  %-14s %6s\n" "dashboard-full" "$(du -h "$OUT/dashboard-full.jpg"|cut -f1)"
echo "total: $(du -sh "$OUT"|cut -f1)"
