#!/bin/bash
# Rebuild website/media/ and the README media in docs/media/ from the source
# screen recordings in website/Videos/. Only the generated outputs are needed to
# serve the site or render the README; Videos/ is the master.
#
# STALE AS OF THE DRAWER REDESIGN -- see RESHOOT.md next to this file. Both
# remaining takes predate it: they show the AI behind an "AI EXPLANATION" tab
# that no longer exists (the analysis is now a panel above the tab strip), so
# `incident.mp4`, `macos-explain.png` and cut [b] of the README GIF all
# demonstrate a click on a control the app does not have. Every timestamp below
# is keyed to those takes and none of them survive a re-record.
#
# ONLY "Dashboard Aegis.mov" and "Ask Aegis.mov" may be used. The older
# Dashboard.mov / Daily Brief.mov / Report Generation.mov predate the Ask Aegis
# nav item -- every frame of them shows a sidebar the app no longer has, so no
# frame of them can appear on the site or in the README. They stay in Videos/
# because they are still the only footage of the Daily Brief and PDF report
# flows; re-record those on the current build before putting them back.
#
# The current sources are H.264 / BT.709 / 8-bit / 2994x1858 and need no colour
# work. The retired ones were HEVC + HDR (BT.2020 primaries, PQ transfer,
# 10-bit) and needed a zscale -> tonemap -> bt709 chain, without which the
# emerald "MONITORING ACTIVE" and the amber MEDIUM badges washed out to grey.
# If a future recording reads bt2020/smpte2084 in `ffmpeg -i`, that chain has to
# come back -- and it must NOT be applied to an already-SDR source, which it
# greys out just as badly in the other direction.
#
# ffmpeg comes from the imageio-ffmpeg wheel (a self-contained static binary):
#   pip install imageio-ffmpeg
# macOS's built-in avconvert can transcode but has no bitrate/CRF control, and
# produced 15 MB for a 14s clip where CRF 26 produces 2 MB. Hence ffmpeg.
set -euo pipefail
cd "$(dirname "$0")"

FF=$(python3 -c "import imageio_ffmpeg as f;print(f.get_ffmpeg_exe())")
SRC=Videos
OUT=media
mkdir -p "$OUT"

CROP="crop=2980:1856:0:0"           # trims the sliver of the window behind
LISTCROP="crop=2300:1180:570:659"   # tight on the event stream

enc () { # name src start duration crop width crf
  local name=$1 src=$2 ss=$3 dur=$4 crop=$5 w=$6 crf=$7
  "$FF" -y -ss "$ss" -t "$dur" -i "$SRC/$src" \
    -vf "$crop,scale=$w:-2:flags=lanczos,fps=30" \
    -c:v libx264 -preset slow -crf "$crf" -pix_fmt yuv420p -g 60 \
    -movflags +faststart -an "$OUT/$name.mp4" -loglevel error
  # first frame becomes the poster, so the page never flashes black
  "$FF" -y -i "$OUT/$name.mp4" -frames:v 1 -q:v 4 "$OUT/$name.jpg" -loglevel error
  printf "  %-14s %6s mp4  %5s poster\n" "$name" \
    "$(du -h "$OUT/$name.mp4"|cut -f1)" "$(du -h "$OUT/$name.jpg"|cut -f1)"
}

echo "building website/media:"
#   Dashboard Aegis.mov is one take: overview -> an event's detail drawer ->
#   the Ask page -> the theme picker -> password-gated Stop Monitoring -> restart.
#   Ask Aegis.mov is: live stream -> drawer + AI EXPLANATION tab -> Ask a
#   question -> the answer, with the timeline events it cites.
enc hero     "Dashboard Aegis.mov"  0.2 20.3 "$CROP"     1600 30  # scrimmed bg, quality can be low
enc memory   "Ask Aegis.mov"        0.3  8.2 "$LISTCROP" 1200 26  # cropped to the event stream
enc incident "Ask Aegis.mov"        7.0  6.2 "$CROP"     1500 26  # click -> drawer -> AI explanation

# Ask Aegis: the chips + the click, then a hard cut past the model round-trip
# (~10s of a thinking indicator) straight to the cited answer. The wait is real
# and the README says so in words; a 10-second dead loop on the page is not.
"$FF" -y -i "$SRC/Ask Aegis.mov" -filter_complex \
  "[0:v]trim=14.6:18.7,setpts=PTS-STARTPTS[a];[0:v]trim=27.6:34.0,setpts=PTS-STARTPTS[b];\
[a][b]concat=n=2:v=1[c];[c]$CROP,scale=1500:-2:flags=lanczos,fps=30[v]" \
  -map "[v]" -c:v libx264 -preset slow -crf 26 -pix_fmt yuv420p -g 60 \
  -movflags +faststart -an "$OUT/ask.mp4" -loglevel error
"$FF" -y -i "$OUT/ask.mp4" -frames:v 1 -q:v 4 "$OUT/ask.jpg" -loglevel error
printf "  %-14s %6s mp4  %5s poster\n" "ask" \
  "$(du -h "$OUT/ask.mp4"|cut -f1)" "$(du -h "$OUT/ask.jpg"|cut -f1)"

# the one full-width static screenshot (its own section, no text over it).
# index.html hardcodes its width/height -- update both if this scale changes.
"$FF" -y -ss 1.0 -i "$SRC/Dashboard Aegis.mov" -vf "$CROP,scale=2400:-2:flags=lanczos" \
  -frames:v 1 -q:v 3 "$OUT/dashboard-full.jpg" -loglevel error
printf "  %-14s %6s  %s\n" "dashboard-full" "$(du -h "$OUT/dashboard-full.jpg"|cut -f1)" \
  "$("$FF" -i "$OUT/dashboard-full.jpg" -hide_banner 2>&1 | grep -o '[0-9]*x[0-9]*' | head -1)"
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
# 10fps/900px is what keeps it near 4 MB instead of 25 MB -- GitHub serves the
# whole file before the first frame paints, so size IS the load time here.
"$FF" -y -i "$SRC/Dashboard Aegis.mov" -i "$SRC/Ask Aegis.mov" -filter_complex \
  "[0:v]trim=0.2:20.5,setpts=PTS-STARTPTS[a];[1:v]trim=9.4:13.0,setpts=PTS-STARTPTS[b];\
[1:v]trim=14.6:18.7,setpts=PTS-STARTPTS[c];[1:v]trim=27.6:37.0,setpts=PTS-STARTPTS[d];\
[a][b][c][d]concat=n=4:v=1[m];\
[m]$CROP,fps=10,scale=900:-2:flags=lanczos,split[s0][s1];\
[s0]palettegen=stats_mode=diff:max_colors=128[p];\
[s1][p]paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle" \
  "$DOCS/aegis-demo.gif" -loglevel error
printf "  %-22s %6s\n" "aegis-demo.gif" "$(du -h "$DOCS/aegis-demo.gif"|cut -f1)"

shot () { # name src timestamp
  "$FF" -y -ss "$3" -i "$SRC/$2" -vf "$CROP,scale=1600:-2:flags=lanczos" \
    -frames:v 1 "$DOCS/$1.png" -loglevel error
  printf "  %-22s %6s\n" "$1.png" "$(du -h "$DOCS/$1.png"|cut -f1)"
}
shot macos-dashboard "Dashboard Aegis.mov" 1.0    # overview + live event stream
shot macos-explain   "Ask Aegis.mov"       10.6   # drawer, AI EXPLANATION tab open
shot macos-ask       "Ask Aegis.mov"       31.0   # answer with timeline citations
echo "total: $(du -sh "$DOCS"|cut -f1)"
