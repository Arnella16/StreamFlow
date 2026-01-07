import {
  Box,
  Button,
  Center,
  Heading,
  Text,
  VStack,
  useColorModeValue,
  SimpleGrid,
  Image,
  Input,
  useToast,
} from "@chakra-ui/react";
import { FormControl, FormLabel } from "@chakra-ui/react";
import Navbar from "./Navbar";
import { useState, useEffect } from "react";

interface UploadedVideo {
  _id: string;
  title: string;
  description: string;
  author: string;
  path: string;
  thumbnail: string;
  duration: number;
  likes: number;
  views: number;
  comments: Array<{
    user: string;
    text: string;
    createdAt: string;
  }>;
  createdAt: string;
}

interface User {
  _id: string;
  username: string;
  email: string;
  createdAt: string;
  lastLogin: string;
}

interface UploadProps {
  user: User;
  onGoBack: () => void;
}

const UploadPage: React.FC<UploadProps> = ({ user, onGoBack }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadedVideos, setUploadedVideos] = useState<UploadedVideo[]>([]);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [duration, setDuration] = useState<number | null>(null);

  useEffect(() => {
    fetch("http://98.70.25.253:3001/videos")
      .then((res) => res.json())
      .then((data) => setUploadedVideos(data))
      .catch((err) => console.error("Error fetching videos:", err));
  }, []);

  const toast = useToast();

  const cardBg = useColorModeValue("white", "gray.800");
  const borderColor = useColorModeValue("gray.200", "gray.700");

  // Allowed pattern: letters, numbers, spaces, and simple punctuation
  const sanitizeInput = (text: string) => {
    return text.replace(/[^a-zA-Z0-9\s.,!?"'()_-]/g, "");
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      const file = event.target.files[0];
      setSelectedFile(file);

      const videoElement = document.createElement("video");
      videoElement.preload = "metadata";
      videoElement.src = URL.createObjectURL(file);

      videoElement.onloadedmetadata = () => {
        setDuration(videoElement.duration);
        URL.revokeObjectURL(videoElement.src);
      };
    }
  };

  const validateInputs = () => {
    if (!selectedFile) {
      toast({
        title: "No file selected",
        status: "warning",
        duration: 2000,
        isClosable: true,
      });
      return false;
    }

    if (!title.trim()) {
      toast({
        title: "Title is required",
        status: "warning",
        duration: 2000,
        isClosable: true,
      });
      return false;
    }

    if (!description.trim()) {
      toast({
        title: "Description is required",
        status: "warning",
        duration: 2000,
        isClosable: true,
      });
      return false;
    }

    const wordCount = description.trim().split(/\s+/).length;
    if (wordCount < 2) {
      toast({
        title: "Description must contain at least 2 words",
        status: "warning",
        duration: 2500,
        isClosable: true,
      });
      return false;
    }

    return true;
  };

  const handleUpload = async () => {
    if (!validateInputs()) return;

    const cleanTitle = sanitizeInput(title.trim());
    const cleanDescription = sanitizeInput(description.trim());

    const formData = new FormData();
    formData.append("video", selectedFile!);
    formData.append("title", cleanTitle);
    formData.append("description", cleanDescription);
    formData.append("uploader", user.username);

    if (duration !== null) {
      formData.append("duration", duration.toString());
    }

    try {
      const res = await fetch("http://98.70.25.253:3001/", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) throw new Error("Upload failed");

      toast({
        title: "Video uploaded successfully!",
        status: "success",
        duration: 2000,
        isClosable: true,
      });

      setSelectedFile(null);
      setTitle("");
      setDescription("");
    } catch (err) {
      toast({
        title: "Upload failed",
        status: "error",
        duration: 2000,
        isClosable: true,
      });
    }
  };

  return (
    <Box minH="100vh" bg={useColorModeValue("gray.100", "gray.900")} pt="80px" px={4}>
      <Navbar />
      <Center>
        <Box
          w="full"
          maxW="4xl"
          bg={cardBg}
          boxShadow="2xl"
          borderRadius="xl"
          borderWidth="1px"
          borderColor={borderColor}
          p={10}
        >
          <VStack gap={6} align="stretch">
            <Heading size="md" color="gray.600">
              Hello, {user.username}
            </Heading>

            <Heading size="lg" color={useColorModeValue("blue.600", "blue.300")}>
              Upload Your Video
            </Heading>

            <VStack align="stretch" gap={4}>
              <FormControl isRequired>
                <FormLabel>Choose Video File <Text as="span" color="red.500"></Text></FormLabel>
                <Input
                  type="file"
                  accept="video/*"
                  onChange={handleFileChange}
                  bg={useColorModeValue("gray.50", "gray.700")}
                />
              </FormControl>

              <FormControl isRequired>
                <FormLabel>Video Title <Text as="span" color="red.500"></Text></FormLabel>
                <Input
                  placeholder="Enter video title"
                  value={title}
                  onChange={(e) => setTitle(sanitizeInput(e.target.value))}
                />
              </FormControl>

              <FormControl isRequired>
                <FormLabel>Video Description <Text as="span" color="red.500"></Text></FormLabel>
                <Input
                  placeholder="Enter video description (at least 2 words)"
                  value={description}
                  onChange={(e) => setDescription(sanitizeInput(e.target.value))}
                />
              </FormControl>

              <Button
                onClick={handleUpload}
                colorScheme="blue"
                size="md"
                isDisabled={!selectedFile || !title || !description}
              >
                Upload Video
              </Button>
            </VStack>

            <Heading size="md" mt={8}>
              Videos
            </Heading>

            {uploadedVideos.length === 0 ? (
              <Text color={useColorModeValue("gray.600", "gray.400")}>
                You haven’t uploaded any videos yet.
              </Text>
            ) : (
              <SimpleGrid columns={[1, 2, 3]} spacing={5} mt={2}>
                {uploadedVideos.map((video) => (
                  <Box
                    key={video._id}
                    borderWidth="1px"
                    borderRadius="md"
                    overflow="hidden"
                    boxShadow="sm"
                  >
                    <Image
                      src={video.thumbnail}
                      alt={video.title}
                      w="full"
                      h="150px"
                      objectFit="cover"
                    />
                    <Box p={3}>
                      <Text fontWeight="bold">{video.title}</Text>
                    </Box>
                  </Box>
                ))}
              </SimpleGrid>
            )}

            <Button onClick={onGoBack} colorScheme="blue" size="sm" alignSelf="flex-start">
              ← Back to Dashboard
            </Button>
          </VStack>
        </Box>
      </Center>
    </Box>
  );
};

export default UploadPage;