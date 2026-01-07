import React, { useRef, useEffect, useState } from "react";
import {
  Box,
  Button,
  AspectRatio,
  Text,
  VStack,
  Divider,
  Heading,
  Input,
} from "@chakra-ui/react";

interface PlaybackPageProps {
  video: {
    id: string;
    title: string;
    src: string;
    thumbnail: string;
    channel?: string;
    views?: string;
  };
  onGoBack?: () => void;
  onGoDashboard?: () => void;
}

const PlaybackPage: React.FC<PlaybackPageProps> = ({
  video,
  onGoBack,
  onGoDashboard,
}) => {
  console.log("🎬 Video prop:", video);
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [likes, setLikes] = useState<number>(0);
  const [comments, setComments] = useState<string[]>([]);
  const [newComment, setNewComment] = useState("");

  // ✅ Fetch like/comment data
  useEffect(() => {
    fetch(`http://98.70.25.253:3002/video/${video.id}`)
      .then((res) => res.json())
      .then((data) => {
        if (data.likes !== undefined) setLikes(data.likes);
        if (data.comments) setComments(data.comments);
      })
      .catch(() => {});
  }, [video]);

  // ✅ Start video & count views on play
  useEffect(() => {
    if (!videoRef.current) return;

    videoRef.current.currentTime = 0;
    const playPromise = videoRef.current.play();
    if (playPromise?.catch) playPromise.catch(() => {});

    const handlePlay = () => {
      fetch(`http://98.70.25.253:3002/videos/${video.id}/view`, {
        method: "POST",
      }).catch(() => {});
    };

    videoRef.current.addEventListener("play", handlePlay);
    return () =>
      videoRef.current?.removeEventListener("play", handlePlay);
  }, [video]);

  // ✅ Keyboard shortcuts handler
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const vid = videoRef.current;
      if (!vid) return;

      switch (e.key) {
        case " ":
          e.preventDefault();
          vid.paused ? vid.play() : vid.pause();
          break;

        case "ArrowRight":
          vid.currentTime += 10;
          break;

        case "ArrowLeft":
          vid.currentTime -= 10;
          break;

        case "ArrowUp":
          vid.volume = Math.min(1, vid.volume + 0.1);
          break;

        case "ArrowDown":
          vid.volume = Math.max(0, vid.volume - 0.1);
          break;

        case "m":
          vid.muted = !vid.muted;
          break;

        case "f":
          if (!document.fullscreenElement) vid.requestFullscreen();
          else document.exitFullscreen();
          break;

        default:
          break;
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // ✅ Like handler
  const handleLike = () => {
    fetch(`http://98.70.25.253:3002/videos/${video.id}/like`, {
      method: "POST",
    })
      .then(() => setLikes((prev) => prev + 1))
      .catch(() => {});
  };

  // ✅ Comment handler
  const handleComment = () => {
    if (!newComment.trim()) return;

    fetch(`http://98.70.25.253:3002/videos/${video.id}/comment`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: newComment }),
    })
      .then(() => {
        setComments((prev) => [...prev, newComment]);
        setNewComment("");
      })
      .catch(() => {});
  };

  return (
    <Box minH="100vh" bg="black" color="white" px={4} py={6}>
      {/* ✅ Top Navigation */}
      <Box display="flex" justifyContent="space-between" mb={4}>
        <Button onClick={onGoBack} colorScheme="blue" size="sm">
          ⬅ Back
        </Button>

        {onGoDashboard && (
          <Button onClick={onGoDashboard} colorScheme="green" size="sm">
            🏠 Dashboard
          </Button>
        )}
      </Box>

      <Box display="flex" gap={6}>
        {/* ✅ LEFT: VIDEO PLAYER */}
        <Box flex="3">
          <AspectRatio ratio={16 / 9} bg="black" mb={4}>
            <video
              ref={videoRef}
              src={video.src}
              controls
              style={{ width: "100%", height: "100%", backgroundColor: "black" }}
            />
          </AspectRatio>

          <Text fontSize="2xl" fontWeight="bold">
            {video.title}
          </Text>
          <Text fontSize="sm" color="gray.400">
            {video.channel ?? "Uploaded by You"} • {video.views ?? "0"} views
          </Text>
        </Box>

        {/* ✅ RIGHT: Sidebar */}
        <Box flex="1" bg="gray.900" p={4} borderRadius="md">
          <Heading size="md" mb={3}>
            ❤️ Likes & 💬 Comments
          </Heading>

          <Box mb={3}>
            <Text fontWeight="bold" mb={2}>
              Likes: {likes}
            </Text>
            <Button colorScheme="pink" size="sm" onClick={handleLike}>
              ❤️ Like
            </Button>
          </Box>

          <Divider my={4} borderColor="gray.700" />

          <VStack align="stretch" spacing={3}>
            <Text fontWeight="bold">Comments:</Text>

            {comments.length ? (
              comments.map((c, idx) => (
                <Box key={idx} p={2} bg="gray.800" borderRadius="md">
                  {c}
                </Box>
              ))
            ) : (
              <Text color="gray.500">No comments yet.</Text>
            )}

            <Divider borderColor="gray.700" />

            <Box display="flex" gap={2}>
              <Input
                placeholder="Add a comment..."
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                bg="gray.800"
                border="none"
                color="white"
                _placeholder={{ color: "gray.500" }}
              />
              <Button colorScheme="teal" size="sm" onClick={handleComment}>
                💬 Post
              </Button>
            </Box>
          </VStack>
        </Box>
      </Box>
    </Box>
  );
};

export default PlaybackPage;
