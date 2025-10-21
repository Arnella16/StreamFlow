// ...existing code...
export type SampleVideo = {
  id: string;
  title: string;
  thumbnail: string;
  src: string;
  channel: string;
  views: string;
  timestamp: string;
};

export const SAMPLE_VIDEOS: SampleVideo[] = [
  {
    id: "1",
    title: "Big Buck Bunny — Sample",
    thumbnail: "https://picsum.photos/seed/1/640/360",
    src: "https://www.w3schools.com/html/mov_bbb.mp4",
    channel: "Sample Channel",
    views: "1.2M",
    timestamp: "10:34",
  },
  {
    id: "2",
    title: "Sample Clip 2",
    thumbnail: "https://picsum.photos/seed/2/640/360",
    src: "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4",
    channel: "Demo Channel",
    views: "856K",
    timestamp: "02:12",
  },
  {
    id: "3",
    title: "Sample Clip 3",
    thumbnail: "https://picsum.photos/seed/3/640/360",
    src: "https://www.w3schools.com/html/mov_bbb.mp4",
    channel: "Demo Channel",
    views: "623K",
    timestamp: "08:40",
  },
  {
    id: "4",
    title: "Sample Clip 4",
    thumbnail: "https://picsum.photos/seed/4/640/360",
    src: "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4",
    channel: "Demo Channel",
    views: "945K",
    timestamp: "05:20",
  },
];