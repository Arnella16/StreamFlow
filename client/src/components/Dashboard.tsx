import {
  Box,
  Button,
  Text,
  VStack,
  HStack,
  Center,
  useColorModeValue,
  Heading,
  Card,
  CardHeader,
  CardBody,
  Avatar,
  Badge,
  Divider,
} from "@chakra-ui/react";
import { useState, useEffect } from "react";
import Navbar from "./Navbar";

interface User {
  _id: string;
  username: string;
  email: string;
  createdAt: string;
  lastLogin: string;
}

interface DashboardProps {
  user: User;
  onLogout: () => void;
  onViewProfile: () => void;
  onGoToUpload: () => void;
  onWatchVideos: () => void;
}

const Dashboard = ({ user, onLogout, onViewProfile, onGoToUpload, onWatchVideos }: DashboardProps) => {
  const [profile, setProfile] = useState<User | null>(user);
  const [loading, setLoading] = useState(false);

  const cardBg = useColorModeValue("white", "gray.800");
  const borderColor = useColorModeValue("gray.200", "gray.700");

  const fetchProfile = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('auth_token');
      const res = await fetch("/api/profile", {
        method: "GET",
        headers: { 
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json" 
        },
      });

      if (res.ok) {
        const data = await res.json();
        setProfile(data);
      } else {
        console.error("Failed to fetch profile");
      }
    } catch (err) {
      console.error("Error fetching profile:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_info');
    onLogout();
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <Box minH="100vh" bg={useColorModeValue("gray.100", "gray.900")} pt="80px" px={4}>
      <Navbar />
      <Center>
        <Box w="full" maxW="4xl">
          <VStack gap={6} align="stretch">
            <HStack justify="space-between">
              <Heading size="lg" color={useColorModeValue("blue.600", "blue.300")}>
                Welcome back, {profile?.username}!
              </Heading>
              <Button colorScheme="red" variant="outline" onClick={handleLogout}>
                Logout
              </Button>
            </HStack>

            <Card bg={cardBg} borderColor={borderColor}>
              <CardHeader>
                <HStack>
                  <Avatar name={profile?.username} size="md" />
                  <VStack align="start" spacing={1}>
                    <Heading size="md">{profile?.username}</Heading>
                    <Text color="gray.500" fontSize="sm">{profile?.email}</Text>
                  </VStack>
                  <Badge colorScheme="green" ml="auto">Active</Badge>
                </HStack>
              </CardHeader>
              
              <Divider />
              
              <CardBody>
                <VStack align="start" spacing={3}>
                  <Box>
                    <Text fontWeight="semibold" color="gray.600" fontSize="sm">User ID</Text>
                    <Text fontFamily="mono" fontSize="sm">{profile?._id}</Text>
                  </Box>
                  
                  <Box>
                    <Text fontWeight="semibold" color="gray.600" fontSize="sm">Member Since</Text>
                    <Text>{profile?.createdAt ? formatDate(profile.createdAt) : 'N/A'}</Text>
                  </Box>
                  
                  <Box>
                    <Text fontWeight="semibold" color="gray.600" fontSize="sm">Last Login</Text>
                    <Text>{profile?.lastLogin ? formatDate(profile.lastLogin) : 'N/A'}</Text>
                  </Box>
                </VStack>
              </CardBody>
            </Card>

            <Card bg={cardBg} borderColor={borderColor}>
              <CardHeader>
                <Heading size="md">Quick Actions</Heading>
              </CardHeader>
              <CardBody>
                <HStack spacing={4}>
                  <Button 
                    colorScheme="blue" 
                    onClick={fetchProfile}
                    isLoading={loading}
                    loadingText="Refreshing..."
                  >
                    Refresh Profile
                  </Button>
                  <Button variant="outline" colorScheme="blue" onClick={onViewProfile}>
                    My Profile
                  </Button>

                  <Button variant="outline" colorScheme="blue" onClick={onGoToUpload}>
                    Upload New Content
                  </Button>

                  <Button variant="outline" colorScheme="blue" onClick={onWatchVideos}>
                    Watch videos
                  </Button>
                </HStack>
              </CardBody>
            </Card>

            <Box textAlign="center" pt={4}>
              <Text color="gray.500" fontSize="sm">
                🎉 Your StreamFlow account is set up and ready to go!
              </Text>
            </Box>
          </VStack>
        </Box>
      </Center>
    </Box>
  );
};

export default Dashboard;
