import VideoCard from "./VideoCard";
import thumb1 from "../../assets/thumb1.jpg";
import thumb2 from "../../assets/thumb2.jpg";
import thumb3 from "../../assets/thumb3.jpg";
import thumb4 from "../../assets/thumb4.jpg";
import thumb5 from "../../assets/thumb5.jpg";
import thumb6 from "../../assets/thumb6.jpg";
import { SimpleGrid, Heading, Box } from "@chakra-ui/react";

const videos = [
  { id: 1, thumbnail: thumb1, title: "Modern Technology Explained - Complete Guide for Beginners", channel: "Tech Insights", views: "1.2M", timestamp: "12:45" },
  { id: 2, thumbnail: thumb2, title: "Creative Design Workspace Tour - My Setup 2024", channel: "Design Studio", views: "856K", timestamp: "8:30" },
  { id: 3, thumbnail: thumb3, title: "Digital Innovation: The Future is Now", channel: "Future Tech", views: "2.1M", timestamp: "15:20" },
  { id: 4, thumbnail: thumb4, title: "Entertainment and Media Production Behind the Scenes", channel: "Media Pro", views: "623K", timestamp: "10:15" },
  { id: 5, thumbnail: thumb5, title: "Educational Content Creation - Tips and Tricks", channel: "Learn Hub", views: "945K", timestamp: "18:42" },
  { id: 6, thumbnail: thumb6, title: "Music Production Masterclass - Full Tutorial", channel: "Audio Academy", views: "1.5M", timestamp: "25:10" },
];

const VideoGrid = () => {
  return (
    <Box>
      <Heading size="lg" mb={6}>
        Recommended for you
      </Heading>
      <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={6}>
        {videos.map((v) => (
          <VideoCard key={v.id} {...v} />
        ))}
      </SimpleGrid>
    </Box>
  );
};

export default VideoGrid;