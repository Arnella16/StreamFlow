import {
  Box,
  Button,
  Center,
  Heading,
  Text,
  VStack,
  Avatar,
  useColorModeValue,
  SimpleGrid,
  Image,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";

interface User {
  _id: string;
  username: string;
  email: string;
  avatarUrl?: string;
}

interface Video {
  id: string;
  title: string;
  thumbnailUrl: string;
  likesCount: number;
  viewsCount: number;
}

interface LikedVideo extends Video {
  likedByUser: boolean;
  userComment: string;
}

interface UserProfileProps {
  user: User;          // required user
  onGoBack: () => void;  // optional back function
}

const UserProfile: React.FC<UserProfileProps> = ({ user, onGoBack }) => {
  const [videos, setVideos] = useState<Video[]>([
    {
    id: "1",
    title: "Dummy Video",
    thumbnailUrl: "https://via.placeholder.com/150",
    likesCount: 10,
    viewsCount: 100,
  },
  ]);

  const [likedVideos] = useState<LikedVideo[]>([
    {
      id: "101",
      title: "Funny Cat Video",
      thumbnailUrl: "https://via.placeholder.com/150",
      likesCount: 50,
      viewsCount: 500,
      likedByUser: true,          // dummy like
      userComment: "So cute! 😻", // dummy comment
    },
    {
      id: "102",
      title: "Amazing Travel Vlog",
      thumbnailUrl: "https://via.placeholder.com/150",
      likesCount: 120,
      viewsCount: 1000,
      likedByUser: true,
      userComment: "I want to go there! ✈️",
    },
  ]);


  const cardBg = useColorModeValue("white", "gray.800");
  const borderColor = useColorModeValue("gray.200", "gray.700");

  useEffect(() => {

    // get user's uploaded videos (adjust URL to your API)
    const token = localStorage.getItem("auth_token");
    if (token) {
      fetch("http://localhost:5000/api/videos/my", {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((res) => res.json())
        .then((data) => setVideos(data))
        .catch((err) => console.error("Error fetching videos:", err));
    }
  }, []);

  

  const handleLogout = () => {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("user_info");
    window.location.href = "/login"; // redirect to login
  };

  if (!user) {
    return (
      <Center minH="100vh">
        <Text>Loading your profile...</Text>
      </Center>
    );
  }

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

            <Button
              onClick={onGoBack}
              colorScheme="blue"
              size="md"
              alignSelf="flex-start"
            >
              ← Go Back to Dashboard
            </Button>

            <Center>
              <VStack>
                <Avatar
                  size="xl"
                  name={user.username}
                  src={user.avatarUrl || undefined}
                  mb={2}
                />
                <Heading size="lg" color={useColorModeValue("blue.600", "blue.300")}>
                  {user.username}
                </Heading>
                <Text color={useColorModeValue("gray.600", "gray.400")}>{user.email}</Text>
              </VStack>
            </Center>

            <Heading size="md" mt={8}>
              Your Uploaded Videos
            </Heading>
            {videos.length === 0 ? (
              <Text color={useColorModeValue("gray.600", "gray.400")}>
                You haven’t uploaded any videos yet.
              </Text>
            ) : (
              <SimpleGrid columns={[1, 2, 3]} spacing={5} mt={2}>
                {videos.map((video) => (
                  <Box
                    key={video.id}
                    borderWidth="1px"
                    borderRadius="md"
                    overflow="hidden"
                    boxShadow="sm"
                  >
                    <Image
                      src={video.thumbnailUrl}
                      alt={video.title}
                      w="full"
                      h="150px"
                      objectFit="cover"
                    />
                    <Box p={3}> 
                        <Text fontWeight="semibold">{video.title}</Text> 
                        <Text fontSize="sm" color="gray.500"> {video.likesCount} likes • {video.viewsCount} views </Text>
                    </Box>
                  </Box>
                ))}
              </SimpleGrid>
            )}

            <Heading size="md" mt={12}>Videos You Liked / Commented On</Heading>

            {likedVideos.length === 0 ? (
            <Text color={useColorModeValue("gray.600", "gray.400")}>
                You haven’t liked or commented on any videos yet.
            </Text>
            ) : (
            <SimpleGrid columns={[1, 2, 3]} spacing={5} mt={2}>
                {likedVideos.map((video) => (
                <Box key={video.id} borderWidth="1px" borderRadius="md" overflow="hidden" boxShadow="sm">
                    <Image
                    src={video.thumbnailUrl}
                    alt={video.title}
                    w="full"
                    h="150px"
                    objectFit="cover"
                    />
                    <Box p={3}>
                    <Text fontWeight="semibold">{video.title}</Text>
                    <Text fontSize="sm" color="gray.500">
                        {video.likesCount} likes • {video.viewsCount} views
                    </Text>

                    {/* Your like & comment on this video */}
                    <Box mt={2} p={2} bg={useColorModeValue("gray.50", "gray.700")} borderRadius="md">
                        <Text fontSize="sm" fontWeight="bold" mb={1}>Your Likes:</Text>
                        <Text fontSize="sm">{video.likedByUser ? "Liked 👍" : "Not liked"}</Text>

                        <Text fontSize="sm" fontWeight="bold" mt={2} mb={1}>Your Comments:</Text>
                        <Text fontSize="sm">{video.userComment || "No comment"}</Text>
                    </Box>
                    </Box>
                </Box>
                ))}
            </SimpleGrid>
            )}

            <Center>
              <Button
                onClick={handleLogout}
                colorScheme="red"
                size="lg"
                fontWeight="bold"
                mt={6}
              >
                Logout
              </Button>
            </Center>
          </VStack>
        </Box>
      </Center>
    </Box>
  );
};

export default UserProfile;
