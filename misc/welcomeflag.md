# misc/WelcomeFlag

## Overview

This challenge gives us a single hint: “Do you know semaphore? What he is saying?” That tells us the important part immediately. The attached artifact is a message encoded in semaphore flag positions.

If we inspect the video or render a quick contact sheet, we can see a stick figure holding two red/yellow semaphore flags and changing pose over time. So the entire task becomes:

1. Extract the held flag positions from the video.
2. Turn those positions into semaphore letters.
3. Read the plaintext message and wrap it in the provided flag format.

## Exploit Chain

1. Confirm the artifact and the encoding type

The challenge description already tells us the signal system to use: semaphore. After extracting the zip, the only file is `flag.mp4`, so there is no hidden binary or network step. The payload is in the video itself.

A quick metadata check shows it is a 60 FPS video:

```bash
ffprobe -hide_banner flag.mp4
```

That matters because the figure does not instantly jump between letters. Each real letter is held for a longer period, and the in-between frames are just transitions.

2. Visually verify what the video contains

To avoid guessing, it is useful to render one frame per second into a contact sheet:

```bash
ffmpeg -hide_banner -loglevel error -i flag.mp4 -vf "fps=1,scale=640:-1,tile=5x9" -frames:v 1 contact.jpg
```

Looking at that output shows a static stick figure on a dark background. Only the arms and flags move. That observation is important because it tells us we do not need pose estimation, OCR, or anything heavy. We only need to track the two bright flag blobs.

3. Detect the two flags in every frame

The flags are the only saturated bright objects in the entire frame. Converting each frame to HSV and thresholding high saturation and high value isolates them cleanly.

From there, `connectedComponentsWithStats` gives the flag blobs and their centroids. In normal frames there are exactly two large components, one for each flag.

This gives us two `(x, y)` points per frame.

4. Track the same arm across the full video

The next problem is identity. We do not just need two points, we need the same arm to stay in the same slot through the whole decode process.

The fix is simple:

1. On the first frame, sort the two flag centroids by x-position.
2. On every later frame, assign the new two centroids to the previous two tracked positions with the minimum movement cost.

Because the animation is smooth, the correct assignment is always the one with the shortest total travel distance. This stabilizes the pose sequence even when the arms cross.

5. Learn the actual hand positions used by the animation

The video does not use arbitrary coordinates. It uses a small fixed set of hand positions:

- straight up on the left and right
- upper-left and upper-right
- left and right horizontal
- lower-left and lower-right
- straight down on the left and right

That is 10 total screen positions.

Instead of hardcoding pixel coordinates, we can collect all detected flag centroids from the entire video and cluster them with k-means into 10 centers. Once we sort those cluster centers from top to bottom and left to right, we can label them as:

- `UPl`, `UPr`
- `UL`, `UR`
- `L`, `R`
- `DL`, `DR`
- `DNl`, `DNr`

After that, every tracked flag point in every frame can be snapped to its nearest named position.

6. Separate real letters from transition frames

If we convert every frame directly into a semaphore pair, the output is noisy because the animation spends a few frames moving between letters.

The correct way to handle this is run-length encoding:

1. Convert every frame into a named pose pair.
2. Compress consecutive identical poses into `(start, end, pose)` runs.
3. Keep only long runs.

In this challenge the video is 60 FPS, and each actual letter is held for roughly 70 to 80 frames. Transition poses are much shorter. Using a threshold of about `fps` frames cleanly separates letters from movement.

We also ignore the rest pose `("DNl", "DNr")`, which appears at the beginning and end and does not encode a letter.

7. Map semaphore pairs to letters

Now we apply the standard semaphore alphabet. The only thing that matters is consistency: our script labels the two tracked arms in a fixed order, so the mapping dictionary must use that same order.

The relevant mapping used by the solver is:

```python
SEMAPHORE_TO_CHAR = {
    ("DL", "DNr"): "a",
    ("L", "DNr"): "b",
    ("UL", "DNr"): "c",
    ("UPl", "DNr"): "d",
    ("DNl", "UR"): "e",
    ("DNl", "R"): "f",
    ("DNl", "DR"): "g",
    ("L", "DNl"): "h",
    ("UL", "DNl"): "i",
    ("UPl", "R"): "j",
    ("DL", "UPr"): "k",
    ("DL", "UR"): "l",
    ("DL", "R"): "m",
    ("DL", "DR"): "n",
    ("UL", "L"): "o",
    ("L", "UPr"): "p",
    ("L", "UR"): "q",
    ("L", "R"): "r",
    ("L", "DR"): "s",
    ("UL", "UPr"): "t",
    ("UL", "UR"): "u",
    ("UPl", "DR"): "v",
    ("R", "UR"): "w",
    ("UR", "DR"): "x",
    ("UL", "R"): "y",
    ("R", "DR"): "z",
}
```

Decoding the long stable runs gives:

```text
welcometocodegatectfhavefun
```

8. Build the flag

The challenge tells us the format is:

```text
codegate2026{[a-z]+}
```

So the final flag is:

```text
codegate2026{welcometocodegatectfhavefun}
```

## Final Solve

```python
#!/usr/bin/env python3

import argparse
import itertools
from pathlib import Path

import cv2
import numpy as np


REST_POSE = ("DNl", "DNr")

# Pose names are from the viewer's perspective:
# UPl/UPr = straight up on the left/right side of the image
# UL/UR   = upper-left / upper-right diagonal
# L/R     = horizontal left / horizontal right
# DL/DR   = lower-left / lower-right diagonal
# DNl/DNr = straight down on the left/right side of the image
SEMAPHORE_TO_CHAR = {
    ("DL", "DNr"): "a",
    ("L", "DNr"): "b",
    ("UL", "DNr"): "c",
    ("UPl", "DNr"): "d",
    ("DNl", "UR"): "e",
    ("DNl", "R"): "f",
    ("DNl", "DR"): "g",
    ("L", "DNl"): "h",
    ("UL", "DNl"): "i",
    ("UPl", "R"): "j",
    ("DL", "UPr"): "k",
    ("DL", "UR"): "l",
    ("DL", "R"): "m",
    ("DL", "DR"): "n",
    ("UL", "L"): "o",
    ("L", "UPr"): "p",
    ("L", "UR"): "q",
    ("L", "R"): "r",
    ("L", "DR"): "s",
    ("UL", "UPr"): "t",
    ("UL", "UR"): "u",
    ("UPl", "DR"): "v",
    ("R", "UR"): "w",
    ("UR", "DR"): "x",
    ("UL", "R"): "y",
    ("R", "DR"): "z",
}


def detect_flag_centroids(frame: np.ndarray) -> list[np.ndarray]:
    hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)

    # The semaphore flags are the only saturated, bright objects in the frame.
    mask = ((hsv[:, :, 1] > 80) & (hsv[:, :, 2] > 80)).astype("uint8")
    component_count, _, stats, centroids = cv2.connectedComponentsWithStats(mask, 8)

    points: list[np.ndarray] = []
    for index in range(1, component_count):
        area = stats[index, cv2.CC_STAT_AREA]
        if area > 300:
            points.append(np.array(centroids[index], dtype=np.float32))

    return points


def track_flags(video_path: Path) -> tuple[float, list[np.ndarray | None], np.ndarray]:
    capture = cv2.VideoCapture(str(video_path))
    if not capture.isOpened():
        raise RuntimeError(f"failed to open video: {video_path}")

    fps = capture.get(cv2.CAP_PROP_FPS) or 60.0
    tracked_frames: list[np.ndarray | None] = []
    all_points: list[np.ndarray] = []
    previous: list[np.ndarray] | None = None

    while True:
        ok, frame = capture.read()
        if not ok:
            break

        points = detect_flag_centroids(frame)
        if len(points) != 2:
            tracked_frames.append(None)
            continue

        if previous is None:
            ordered = sorted(points, key=lambda point: point[0])
        else:
            best_cost = None
            best_order = None
            for permutation in itertools.permutations(range(2)):
                cost = sum(
                    np.sum((points[permutation[i]] - previous[i]) ** 2)
                    for i in range(2)
                )
                if best_cost is None or cost < best_cost:
                    best_cost = cost
                    best_order = permutation

            assert best_order is not None
            ordered = [points[best_order[0]], points[best_order[1]]]

        previous = ordered
        tracked = np.array(ordered, dtype=np.float32)
        tracked_frames.append(tracked)
        all_points.extend(tracked)

    capture.release()

    if not all_points:
        raise RuntimeError("no flag positions were detected")

    return fps, tracked_frames, np.array(all_points, dtype=np.float32)


def cluster_pose_centers(points: np.ndarray) -> dict[str, np.ndarray]:
    criteria = (
        cv2.TERM_CRITERIA_EPS + cv2.TERM_CRITERIA_MAX_ITER,
        100,
        0.2,
    )
    _, _, centers = cv2.kmeans(
        points,
        10,
        None,
        criteria,
        25,
        cv2.KMEANS_PP_CENTERS,
    )

    centers = centers[np.argsort(centers[:, 1])]
    if len(centers) != 10:
        raise RuntimeError("expected 10 hand positions after clustering")

    row_names = [
        ("UPl", "UPr"),
        ("UL", "UR"),
        ("L", "R"),
        ("DL", "DR"),
        ("DNl", "DNr"),
    ]

    named_centers: dict[str, np.ndarray] = {}
    for row_index, names in enumerate(row_names):
        row = centers[row_index * 2 : (row_index + 1) * 2]
        row = row[np.argsort(row[:, 0])]
        named_centers[names[0]] = row[0]
        named_centers[names[1]] = row[1]

    return named_centers


def quantize_frames(
    tracked_frames: list[np.ndarray | None],
    named_centers: dict[str, np.ndarray],
) -> list[tuple[str, str]]:
    pose_names = list(named_centers.keys())
    center_array = np.array([named_centers[name] for name in pose_names], dtype=np.float32)

    sequence: list[tuple[str, str]] = []
    last_pose: tuple[str, str] | None = None

    for tracked in tracked_frames:
        if tracked is None:
            if last_pose is not None:
                sequence.append(last_pose)
            continue

        pose = []
        for point in tracked:
            index = int(np.argmin(np.sum((center_array - point) ** 2, axis=1)))
            pose.append(pose_names[index])

        pose_tuple = (pose[0], pose[1])
        sequence.append(pose_tuple)
        last_pose = pose_tuple

    return sequence


def run_length_encode(sequence: list[tuple[str, str]]) -> list[tuple[int, int, tuple[str, str]]]:
    if not sequence:
        return []

    runs: list[tuple[int, int, tuple[str, str]]] = []
    start = 0
    current = sequence[0]

    for index, pose in enumerate(sequence[1:], start=1):
        if pose != current:
            runs.append((start, index - 1, current))
            start = index
            current = pose

    runs.append((start, len(sequence) - 1, current))
    return runs


def decode_message(video_path: Path) -> str:
    fps, tracked_frames, all_points = track_flags(video_path)
    named_centers = cluster_pose_centers(all_points)
    sequence = quantize_frames(tracked_frames, named_centers)
    runs = run_length_encode(sequence)

    # In this video, real letters are held for roughly 1.2 seconds.
    # Shorter runs are just transitions between letters.
    minimum_letter_frames = max(1, int(fps))

    decoded = []
    for start, end, pose in runs:
        duration = end - start + 1
        if duration < minimum_letter_frames or pose == REST_POSE:
            continue

        character = SEMAPHORE_TO_CHAR.get(pose)
        if character is None:
            raise RuntimeError(f"unknown semaphore pose: {pose}")

        decoded.append(character)

    return "".join(decoded)


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve the WelcomeFlag semaphore challenge")
    parser.add_argument(
        "video",
        nargs="?",
        default="flag.mp4",
        help="path to the challenge video (default: flag.mp4)",
    )
    parser.add_argument(
        "--prefix",
        default="codegate2026",
        help="flag prefix to print (default: codegate2026)",
    )
    args = parser.parse_args()

    message = decode_message(Path(args.video))
    print(f"decoded message: {message}")
    print(f"{args.prefix}{{{message}}}")


if __name__ == "__main__":
    main()
```

Run it like:

```bash
python3 solve.py flag.mp4
```