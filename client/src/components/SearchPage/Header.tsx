import { Flex, Box, Input, Button, useColorModeValue, Icon } from "@chakra-ui/react";
import { Search, Video } from "lucide-react";

const Header = () => {
  const bg = useColorModeValue("white", "gray.800");
  const border = useColorModeValue("gray.200", "gray.700");

  return (
    <Box
      as="header"
      position="sticky"
      top={0}
      zIndex={50}
      bg={bg}
      borderBottom="1px"
      borderColor={border}
      backdropFilter="saturate(180%) blur(6px)"
    >
      <Flex align="center" maxW="7xl" mx="auto" px={{ base: 4, md: 8 }} h="64px" gap={6}>
        <Flex align="center" gap={3} minW="200px">
          <Box
            display="flex"
            alignItems="center"
            justifyContent="center"
            w="10"
            h="10"
            borderRadius="md"
            bg="blue.500"
          >
            <Icon as={Video} color="white" />
          </Box>
          <Box fontWeight="bold" fontSize="lg" bgClip="text" color="blue.600">
            BluePlay
          </Box>
        </Flex>

        <Box flex="1" maxW="2xl">
          <Box position="relative">
            <Search style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", opacity: 0.7 }} />
            <Input
              type="search"
              placeholder="Search videos..."
              pl={12}
              bg={useColorModeValue("gray.50", "gray.700")}
              borderRadius="md"
            />
          </Box>
        </Box>

        <Flex align="center" gap={2} minW="40">
          <Button variant="ghost" size="md" aria-label="upload">
            <Icon as={Video} />
          </Button>
        </Flex>
      </Flex>
    </Box>
  );
};

export default Header;