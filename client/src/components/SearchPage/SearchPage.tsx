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
  thumbnail: string;
  author: string;
  views: number;
  createdAt: string;
}

interface SearchPageProps {
  user?: User;
  onGoBack?: () => void;
  onVideoSelect?: (video: UploadedVideo) => void;
}

const SearchPage: React.FC<SearchPageProps> = ({ onGoBack, onVideoSelect }) => {
  const bg = useColorModeValue("gray.50", "gray.900");

  const [query, setQuery] = useState("");
  const [videos, setVideos] = useState<UploadedVideo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // ✅ Load ALL videos on initial mount
  useEffect(() => {
    const loadAll = async () => {
      try {
        setLoading(true);
        const res = await fetch("http://98.70.25.253:3001/videos");
        const data = await res.json();
        console.log(data)
        setVideos(data);
      } catch (err: any) {
        setError("Failed to load videos");
      } finally {
        setLoading(false);
      }
    };
    loadAll();
  }, []);

  // ✅ Elasticsearch search when typing (debounced)
  useEffect(() => {
    const delay = setTimeout(async () => {
      if (query.trim() === "") {
        // Reload recommended (all videos)
        const res = await fetch("http://98.70.25.253:3001/videos");
        const data = await res.json();
        setVideos(data);
        return;
      }

      try {
        setLoading(true);
        setError("");

        const res = await fetch(
          `http://98.70.25.253:8080/sentence-search?q=${query}`
        );

        if (!res.ok) throw new Error("Search failed");

        const data = await res.json();

        // ✅ Map ES structure into UploadedVideo UI structure
        const mapped = data.map((v: any) => ({
          _id: v.id || v._id || "",
          id: v.id || v._id || "",
          title: v.title || "",
          description: v.description || "",
          src:"http://98.70.25.253:3001" + "/uploads/" + v.id, // adjust if needed
          uploader: v.author || "Unknown",
          views: 0,
          createdAt: "",
        }));
        console.log(mapped)

        setVideos(mapped);
      } catch (err: any) {
        setError("Search error");
      } finally {
        setLoading(false);
      }
    }, 350);

    return () => clearTimeout(delay);
  }, [query]);

  return (
    <Box minH="100vh" bg={bg}>
      <Header />

      <Container maxW="7xl" px={{ base: 4, md: 8 }} py={{ base: 4, md: 6 }}>
        {onGoBack && (
          <Box mb={4}>
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

        <Box mb={8}>
          <Hero />
        </Box>

        <Heading mb={6}>Search / Browse</Heading>

        {/* ✅ Search Input */}
        <Box mb={6} display="flex" gap={3}>
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
              fontSize: "1rem",
            }}
          />
        </Box>

        <Heading size="md" mb={4}>
          {query ? "Search Results" : "Recommended for You"}
        </Heading>

        {/* ✅ Loading / Error / Empty */}
        {loading ? (
          <Spinner size="xl" />
        ) : error ? (
          <Text color="red.400">{error}</Text>
        ) : videos.length === 0 ? (
          <Text>No videos found.</Text>
        ) : (
          // ✅ Render Videos
          <Box
            display="grid"
            gridTemplateColumns={{
              base: "1fr",
              sm: "repeat(2, 1fr)",
              md: "repeat(3, 1fr)",
            }}
            gap={6}
          >
            {videos.map((video) => (
              <Box
              key={video.title}
              onClick={() => onVideoSelect?.(video)}
              cursor="pointer"
              borderRadius="md"
              overflow="hidden"
              bg={useColorModeValue("white", "gray.800")}
              boxShadow="md"
              _hover={{ transform: "scale(1.02)" }}
              transition="0.2s"
            >
              <Box position="relative">
                <AspectRatio ratio={16 / 9}>
                  {video.thumbnail ? (
                    <img
                      src={video.thumbnail}
                      alt={video.title}
                      style={{
                        width: "100%",
                        height: "100%",
                        objectFit: "cover",
                      }}
                    />
                  ) : (
                    <video src={video.fileUrl} muted />
                  )}
                </AspectRatio>
                {/* Optional play overlay */}
                <Box
                  position="absolute"
                  top="50%"
                  left="50%"
                  transform="translate(-50%, -50%)"
                  bg="blackAlpha.600"
                  p={2}
                  borderRadius="full"
                >
                </Box>
              </Box>
             <Box p={3}>
                <Text fontWeight="semibold" noOfLines={1}>
                  {video.title}
                </Text>
                <Text fontSize="sm" color="gray.500" noOfLines={1}>
                  {video.author}
                </Text>
              </Box>
            </Box>
          ))}
          </Box>
        )}
      </Container>
    </Box>
  );
};

export default SearchPage;
