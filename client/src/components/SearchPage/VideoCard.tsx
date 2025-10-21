import { Box, Image, Text, Flex, useColorModeValue } from "@chakra-ui/react";
import type { SampleVideo } from "../../data/sampleVideo";

interface VideoCardProps {
  video: SampleVideo;
  onClick?: (v: SampleVideo) => void;
}

const VideoCard = ({ video, onClick }: VideoCardProps) => {
  const border = useColorModeValue("gray.100", "gray.700");
  const bg = useColorModeValue("white", "gray.800");

  return (
    <Box
      borderRadius="md"
      overflow="hidden"
      bg={bg}
      boxShadow="md"
      borderWidth="1px"
      borderColor={border}
      cursor="pointer"
      onClick={() => onClick?.(video)}
      transition="transform 0.15s ease"
      _hover={{ transform: "translateY(-4px)" }}
    >
      <Box position="relative" w="100%" paddingBottom="56.25%">
        <Image src={video.thumbnail} alt={video.title} objectFit="cover" position="absolute" top={0} left={0} w="100%" h="100%" />
      </Box>

      <Box p={4}>
        <Text fontWeight="semibold" noOfLines={2} mb={2}>
          {video.title}
        </Text>
        <Flex align="center" justify="space-between">
          <Text fontSize="sm" color={useColorModeValue("gray.600", "gray.400")}>{video.channel}</Text>
          <Text fontSize="sm" color={useColorModeValue("gray.600", "gray.400")}>{video.views}</Text>
        </Flex>
      </Box>
    </Box>
  );
};

export default VideoCard;