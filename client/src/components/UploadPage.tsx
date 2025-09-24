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
import { useState } from "react";

interface UploadedVideo {
  filename: string;
  path: string; // server path
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
  const toast = useToast();

  const cardBg = useColorModeValue("white", "gray.800");
  const borderColor = useColorModeValue("gray.200", "gray.700");

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      setSelectedFile(event.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      toast({
        title: "No file selected",
        status: "warning",
        duration: 2000,
        isClosable: true,
      });
      return;
    }

    const formData = new FormData();
    formData.append("video", selectedFile);

    try {
      const res = await fetch("http://localhost:3001/upload", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) throw new Error("Upload failed");

      const data = await res.json();
      // Add new video to list
      setUploadedVideos((prev) => [
        ...prev,
        { filename: selectedFile.name, path: data.path },
      ]);

      toast({
        title: "Video uploaded successfully!",
        status: "success",
        duration: 2000,
        isClosable: true,
      });

      setSelectedFile(null);
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
    <Box minH="100vh" bg={useColorModeValue("gray.100", "gray.900")} py={12} px={4}>
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

            <VStack align="stretch" gap={3}>
              <Input
                type="file"
                accept="video/*"
                onChange={handleFileChange}
                bg={useColorModeValue("gray.50", "gray.700")}
              />
              <Button
                onClick={handleUpload}
                colorScheme="blue"
                size="md"
                isDisabled={!selectedFile}
              >
                Upload Video
              </Button>
            </VStack>

            <Heading size="md" mt={8}>
              Uploaded Videos
            </Heading>

            {uploadedVideos.length === 0 ? (
              <Text color={useColorModeValue("gray.600", "gray.400")}>
                You haven’t uploaded any videos yet.
              </Text>
            ) : (
              <SimpleGrid columns={[1, 2, 3]} spacing={5} mt={2}>
                {uploadedVideos.map((video, idx) => (
                  <Box
                    key={idx}
                    borderWidth="1px"
                    borderRadius="md"
                    overflow="hidden"
                    boxShadow="sm"
                  >
                    <Image
                      src={"https://via.placeholder.com/150"} // placeholder thumbnail
                      alt={video.filename}
                      w="full"
                      h="150px"
                      objectFit="cover"
                    />
                    <Box p={3}>
                      <Text fontWeight="semibold">{video.filename}</Text>
                      <Text fontSize="sm" color="gray.500">
                        Saved at {video.path}
                      </Text>
                    </Box>
                  </Box>
                ))}
              </SimpleGrid>
            )}

            <Button
            onClick={onGoBack}
            colorScheme="blue"
            size="sm"
            alignSelf="flex-start"
            >
            ← Back to Dashboard
            </Button>
          </VStack>
        </Box>
      </Center>
    </Box>
  );
};

export default UploadPage;
