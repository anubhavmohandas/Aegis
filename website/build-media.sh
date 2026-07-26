#!/bin/bash
# Rebuild website/media/ and the README media in docs/media/ from the source
# screen recordings in website/Videos/. Only the generated outputs are needed to
# serve the site or render the README; Videos/ is the master.
#
# The sources fall into two groups, and mixing them up wrecks the colour:
#
#   HDR group  — Dashboard.mov, Daily Brief.mov, Report Generation.mov.
#     HEVC in a .mov container (Chrome and Firefox will not play it) AND HDR
#     (BT.2020 primaries, PQ transfer, 10-bit). A plain convert crushes them to
#     washed-out grey — the emerald "MONITORING ACTIVE" and the amber MEDIUM
#     badges lose their colour entirely. The zscale -> tonemap -> bt709 chain
#     ($TM) is what keeps the brand colours intact.
#
#   SDR group  — Ask Aegis.mov, Dashboard Aegis.mov (recorded later, 2994x1858).
#     Already H.264 / BT.709 / 8-bit. Running $TM over these tonemaps an
#     already-SDR image and greys it out, so they take the plain path below.
#     Check before adding a source: `ffmpeg -i <file>` — bt2020/smpte2084 in the
#     stream line means HDR group, bt709 means SDR group.
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

# ---- SDR sources (no $TM) ----------------------------------------------------
# 2994x1858 full-window captures; the last ~14px is a sliver of the window behind.
SDRCROP="crop=2980:1856:0:0"

# Ask Aegis: the chips + the click, then a hard cut past the model round-trip
# (~10s of a thinking indicator) straight to the cited answer. The wait is real
# and the README says so in words; a 10-second dead loop on the page is not.
"$FF" -y -i "$SRC/Ask Aegis.mov" -filter_complex \
  "[0:v]trim=14.6:18.7,setpts=PTS-STARTPTS[a];[0:v]trim=27.6:34.0,setpts=PTS-STARTPTS[b];\
[a][b]concat=n=2:v=1[c];[c]$SDRCROP,scale=1500:-2:flags=lanczos,fps=30[v]" \
  -map "[v]" -c:v libx264 -preset slow -crf 26 -pix_fmt yuv420p -g 60 \
  -movflags +faststart -an "$OUT/ask.mp4" -loglevel error
"$FF" -y -i "$OUT/ask.mp4" -frames:v 1 -q:v 4 "$OUT/ask.jpg" -loglevel error
printf "  %-14s %6s mp4  %5s poster\n" "ask" \
  "$(du -h "$OUT/ask.mp4"|cut -f1)" "$(du -h "$OUT/ask.jpg"|cut -f1)"
echo "total: $(du -sh "$OUT"|cut -f1)"

# ---- README media (docs/media/) ---------------------------------------------
# Lives here rather than in its own script because it shares the sources, the
# crop, and the ffmpeg binary with everything above.
DOCS=../docs/media
mkdir -p "$DOCS"
echo "building docs/media:"

# The README demo, in four cuts: the dashboard take (stream, drawer, theme,
# password-gated Stop Monitoring), an event's AI EXPLANATION tab, Ask Aegis
# being asked, Ask Aegis answering with citations. ~37s.
# 10fps/900px is what keeps it near 3 MB instead of 25 MB — GitHub serves the
# whole file before the first frame paints, so size IS the load time here.
"$FF" -y -i "$SRC/Dashboard Aegis.mov" -i "$SRC/Ask Aegis.mov" -filter_complex \
  "[0:v]trim=0.2:20.5,setpts=PTS-STARTPTS[a];[1:v]trim=9.4:13.0,setpts=PTS-STARTPTS[b];\
[1:v]trim=14.6:18.7,setpts=PTS-STARTPTS[c];[1:v]trim=27.6:37.0,setpts=PTS-STARTPTS[d];\
[a][b][c][d]concat=n=4:v=1[m];\
[m]$SDRCROP,fps=10,scale=900:-2:flags=lanczos,split[s0][s1];\
[s0]palettegen=stats_mode=diff:max_colors=128[p];\
[s1][p]paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle" \
  "$DOCS/aegis-demo.gif" -loglevel error
printf "  %-22s %6s\n" "aegis-demo.gif" "$(du -h "$DOCS/aegis-demo.gif"|cut -f1)"

shot () { # name src timestamp
  "$FF" -y -ss "$3" -i "$SRC/$2" -vf "$SDRCROP,scale=1600:-2:flags=lanczos" \
    -frames:v 1 "$DOCS/$1.png" -loglevel error
  printf "  %-22s %6s\n" "$1.png" "$(du -h "$DOCS/$1.png"|cut -f1)"
}
shot macos-dashboard "Dashboard Aegis.mov" 1.0    # overview + live event stream
shot macos-explain   "Ask Aegis.mov"       10.6   # drawer, AI EXPLANATION tab open
shot macos-ask       "Ask Aegis.mov"       31.0   # answer with timeline citations
echo "total: $(du -sh "$DOCS"|cut -f1)"
