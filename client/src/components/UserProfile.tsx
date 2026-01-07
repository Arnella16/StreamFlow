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
import Navbar from "./Navbar";

interface User {
  _id: string;
  username: string;
  email: string;
  avatarUrl?: string;
}

interface Video {
  id: string;
  title: string;
  thumbnail: string;
  likesCount: number;
  viewsCount: number;
  comments?: string[];
}

interface LikedVideo extends Video {
  likedByUser: boolean;
  userComment?: string;
}

interface UserProfileProps {
  user: User;
  onGoBack: () => void;
}

const UserProfile: React.FC<UserProfileProps> = ({ user, onGoBack }) => {
  const [videos, setVideos] = useState<Video[]>([]);
  const [likedVideos, setLikedVideos] = useState<LikedVideo[]>([]);
  const cardBg = useColorModeValue("white", "gray.800");
  const borderColor = useColorModeValue("gray.200", "gray.700");

  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (!token) return;

   // ✅ Fetch user's uploaded videos (your uploads)
    fetch("http://98.70.25.253:3001/videos", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data: any[]) => {
        console.log(user);
        const myVideos = data.filter(v => v.channel === user.username);
        const mapped = myVideos.map((v) => ({
          id: v._id || v.id,
          title: v.title || "Untitled Video",
          thumbnail: v.thumbnail || "https://via.placeholder.com/150",
          likesCount: v.likes || 0,
          viewsCount: v.views || 0,
          comments: v.comments || [],
        }));
        setVideos(mapped); // ✅ correct state updated here
      })
      .catch((err) => console.error("Error fetching uploaded videos:", err));


    // ✅ Fetch videos you liked or commented on (likes >= 1 or comments >= 1)
    fetch("http://98.70.25.253:3002/videos", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data: any[]) => {
        const likedOrCommented = data.filter(
          (v) => (v.likes && v.likes >= 1) || (v.comments && v.comments.length >= 1)
        );
        const mapped = likedOrCommented.map((v) => ({
          id: v.id,
          title: v.title,
          thumbnail: v.thumbnail || "https://via.placeholder.com/150",
          likesCount: v.likes || 0,
          viewsCount: v.views || 0,
          likedByUser: v.likes && v.likes > 0,
          userComment: v.comments?.[0] || "",
        }));
        setLikedVideos(mapped);
      })
      .catch((err) => console.error("Error fetching liked/commented videos:", err));
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("auth_token");
    localStorage.removeItem("user_info");
    window.location.href = "/login";
  };

  if (!user) {
    return (
      <Center minH="100vh">
        <Text>Loading your profile...</Text>
      </Center>
    );
  }

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
            <Button onClick={onGoBack} colorScheme="blue" size="md" alignSelf="flex-start">
              ← Back to Dashboard
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

            {/* ✅ My Uploaded Videos */}
            <Heading size="md" mt={8}>
              My Uploaded Videos
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
                      src={video.thumbnail || "https://via.placeholder.com/150"}
                      alt={video.title}
                      w="full"
                      h="150px"
                      objectFit="cover"
                    />
                    <Box p={3}>
                      <Text fontWeight="semibold">{video.title}</Text>
                    </Box>
                  </Box>
                ))}
              </SimpleGrid>
            )}

            {/* ✅ Videos You Liked / Commented On */}
            <Heading size="md" mt={12}>
              Videos You Liked / Commented On
            </Heading>
            {likedVideos.length === 0 ? (
              <Text color={useColorModeValue("gray.600", "gray.400")}>
                You haven’t liked or commented on any videos yet.
              </Text>
            ) : (
              <SimpleGrid columns={[1, 2, 3]} spacing={5} mt={2}>
                {likedVideos.map((video) => (
                  <Box
                    key={video.id}
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
                      <Text fontWeight="semibold">{video.title}</Text>
                      <Text fontSize="sm" color="gray.500">
                        {video.likesCount} likes • {video.viewsCount} views
                      </Text>

                      <Box
                        mt={2}
                        p={2}
                        bg={useColorModeValue("gray.50", "gray.700")}
                        borderRadius="md"
                      >
                        <Text fontSize="sm" fontWeight="bold" mb={1}>
                          Your Likes:
                        </Text>
                        <Text fontSize="sm">
                          {video.likedByUser ? "Liked 👍" : "Not liked"}
                        </Text>

                        <Text fontSize="sm" fontWeight="bold" mt={2} mb={1}>
                          Your Comments:
                        </Text>
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