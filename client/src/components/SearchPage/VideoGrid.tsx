import { SimpleGrid, Heading, Box, Text } from "@chakra-ui/react";
import VideoCard from "./VideoCard";
import { SAMPLE_VIDEOS } from "../../data/sampleVideo";
import type { SampleVideo } from "../../data/sampleVideo";

interface VideoGridProps {
  onVideoSelect?: (v: SampleVideo) => void;
  query?: string; 
}

const VideoGrid = ({ onVideoSelect, query = "" }: VideoGridProps) => {
  const filteredVideos = SAMPLE_VIDEOS.filter((v) =>
    v.title.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <Box>
      <Heading size="lg" mb={6}>
        Recommended for you
      </Heading>

      {filteredVideos.length > 0 ? (
        <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={6}>
          {filteredVideos.map((v) => (
            <VideoCard key={v.id} video={v} onClick={onVideoSelect} />
          ))}
        </SimpleGrid>
      ) : (
        <Text color="gray.500" fontSize="lg">
          No videos found for "{query}".
        </Text>
      )}
    </Box>
  );
};

export default VideoGrid;