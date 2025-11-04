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
import { ArrowLeft } from "lucide-react";

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

const PlaybackPage: React.FC<PlaybackPageProps> = ({ video, onGoBack, onGoDashboard }) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [likes, setLikes] = useState<number>(0);
  const [comments, setComments] = useState<string[]>([]);
  const [newComment, setNewComment] = useState("");

  useEffect(() => {
    fetch(`http://localhost:8081/social/api/video/${video.id}`)
      .then((res) => res.json())
      .then((data) => {
        if (data.likes !== undefined) setLikes(data.likes);
        if (data.comments) setComments(data.comments);
      })
      .catch(() => {});
  }, [video]);

  useEffect(() => {
    if (videoRef.current) {
      videoRef.current.currentTime = 0;
      const p = videoRef.current.play();
      if (p && typeof p.catch === "function") p.catch(() => {});

      // 👇 Add view count update when video starts playing
      const handlePlay = () => {
        fetch(`http://localhost:8081/social/api/videos/${video.id}/view`, { method: "POST" })
          .catch(() => {});
      };
      videoRef.current.addEventListener("play", handlePlay);
      return () => {
        videoRef.current?.removeEventListener("play", handlePlay);
      };
    }
  }, [video]);

  const handleLike = () => {
    fetch(`http://localhost:8081/social/api/videos/${video.id}/like`, { method: "POST" })
      .then(() => setLikes((prev) => prev + 1))
      .catch(() => {});
  };

  const handleComment = () => {
    if (!newComment.trim()) return;
    fetch(`http://localhost:8081/social/api/videos/${video.id}/comment`, {
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
      {/* Top bar with buttons */}
      <Box display="flex" justifyContent="space-between" mb={4}>
        <Button onClick={onGoBack} colorScheme="blue" size="sm">
          ⬅ Back
        </Button>

        {onGoDashboard && (
          <Button onClick={onGoDashboard} colorScheme="green" size="sm">
            🏠 Back to Dashboard
          </Button>
        )}
      </Box>

      {/* Split Layout */}
      <Box display="flex" gap={6}>
        {/* Left: Video Section */}
        <Box flex="3">
          <AspectRatio ratio={16 / 9} bg="black" mb={4}>
            <video
              ref={videoRef}
              src={video.src}
              controls
              style={{ width: "100%", height: "100%", backgroundColor: "black" }}
            />
          </AspectRatio>

          <Box>
            <Text fontSize="2xl" fontWeight="bold">
              {video.title}
            </Text>
            <Text fontSize="sm" color="gray.400">
              {video.channel ?? "Uploaded by you"} • {video.views ?? "0"} views
            </Text>
          </Box>
        </Box>

        {/* Right: Likes & Comments Section */}
        <Box flex="1" bg="gray.900" p={4} borderRadius="md">
          {/* ✅ Added buttons ABOVE Likes & Comments */}
          <Box display="flex" justifyContent="space-between" mb={4}>
            <Button
              onClick={onGoBack}
              leftIcon={<ArrowLeft size={16} />}
              variant="ghost"
              size="sm"
              colorScheme="blue"
            >
              Back to Search
            </Button>

            {onGoDashboard && (
              <Button onClick={onGoDashboard} colorScheme="green" size="sm">
                 Dashboard
              </Button>
            )}
          </Box>

          {/* Existing Likes and Comments Section */}
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
            {comments.length > 0 ? (
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
