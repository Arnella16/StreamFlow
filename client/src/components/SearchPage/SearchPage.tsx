import React, { useState, useEffect } from "react";
import Header from "./Header";
import Hero from "./Hero";
import {
  Container,
  Box,
  Button,
  Heading,
  useColorModeValue,
  Text,
  Spinner,
  AspectRatio,
} from "@chakra-ui/react";
import { ArrowLeft } from "lucide-react";

interface User {
  _id: string;
  username: string;
  email: string;
  createdAt: string;
  lastLogin: string;
}

interface UploadedVideo {
  _id: string;
  title: string;
  description: string;
  fileUrl: string;
  uploader: string;
  views: number;
  createdAt: string;
}

interface SearchPageProps {
  user?: User;
  onGoBack?: () => void;
  onVideoSelect?: (video: UploadedVideo) => void;
}

const SearchPage: React.FC<SearchPageProps> = ({ user, onGoBack, onVideoSelect }) => {
  const bg = useColorModeValue("gray.50", "gray.900");
  const [query, setQuery] = useState("");
  const [videos, setVideos] = useState<UploadedVideo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Fetch videos from backend
  useEffect(() => {
    const fetchVideos = async () => {
      setLoading(true);
      setError("");
      try {
        const res = await fetch("http://localhost:3001/videos");
        if (!res.ok) throw new Error("Failed to fetch videos");
        const data = await res.json();
        setVideos(data);
      } catch (err: any) {
        setError(err.message || "Something went wrong");
      } finally {
        setLoading(false);
      }
    };

    fetchVideos();
  }, []);

  // Filter videos by search query
  const filteredVideos = videos.filter((v) =>
    v.title.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <Box minH="100vh" bg={bg}>
      <Header />

      <Container maxW="7xl" px={{ base: 4, md: 8 }} py={{ base: 4, md: 6 }}>
        {/* Back button */}
        {onGoBack && (
          <Box mb={4} display="flex" justifyContent="flex-start">
            <Button
              onClick={onGoBack}
              leftIcon={<ArrowLeft size={16} />}
              variant="ghost"
              size="sm"
              colorScheme="blue"
            >
              Back to Dashboard
            </Button>
          </Box>
        )}

        {/* Hero section */}
        <Box mb={8}>
          <Hero />
        </Box>

        {/* Search box */}
        <main>
          <Heading mb={6}>Search / Browse</Heading>
          <Box mb={6} display="flex" alignItems="center" gap={3}>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search videos..."
              style={{
                flex: 1,
                padding: "10px 14px",
                borderRadius: "8px",
                border: "1px solid #ccc",
                backgroundColor: useColorModeValue("white", "#1A202C"),
                color: useColorModeValue("black", "white"),
                outline: "none",
                fontSize: "1rem",
              }}
            />
            <Button colorScheme="blue">Search</Button>
          </Box>

          {/* Videos section */}
          <Heading size="md" mb={4}>
            {query ? "Search Results" : "Recommended for You"}
          </Heading>

          {loading ? (
            <Spinner size="xl" />
          ) : error ? (
            <Text color="red.400">{error}</Text>
          ) : filteredVideos.length === 0 ? (
            <Text>No videos found.</Text>
          ) : (
            <Box
              display="grid"
              gridTemplateColumns={{
                base: "1fr",
                sm: "repeat(2, 1fr)",
                md: "repeat(3, 1fr)",
              }}
              gap={6}
            >
              {filteredVideos.map((video) => (
                <Box
                  key={video._id}
                  onClick={() => onVideoSelect?.(video)}
                  cursor="pointer"
                  borderRadius="md"
                  overflow="hidden"
                  bg={useColorModeValue("white", "gray.800")}
                  boxShadow="md"
                  _hover={{ transform: "scale(1.02)" }}
                  transition="0.2s"
                >
                  <AspectRatio ratio={16 / 9}>
                    <video src={video.fileUrl} muted />
                  </AspectRatio>
                  <Box p={3}>
                    <Text fontWeight="semibold" noOfLines={1}>
                      {video.title}
                    </Text>
                    <Text fontSize="sm" color="gray.500" noOfLines={1}>
                      {video.uploader || "Unknown"} • {video.views || 0} views
                    </Text>
                  </Box>
                </Box>
              ))}
            </Box>
          )}
        </main>
      </Container>
    </Box>
  );
};

export default SearchPage;