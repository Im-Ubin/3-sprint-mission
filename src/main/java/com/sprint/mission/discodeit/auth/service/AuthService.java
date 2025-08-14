package com.sprint.mission.discodeit.auth.service;

import com.sprint.mission.discodeit.dto.data.UserDto;
import com.sprint.mission.discodeit.entity.User;
import com.sprint.mission.discodeit.exception.user.UserNotFoundException;
import com.sprint.mission.discodeit.mapper.UserMapper;
import com.sprint.mission.discodeit.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthService {

    private final UserRepository userRepository;
    private final UserMapper userMapper;

    public UserDto getCurrentUserInfo(UserDetails userDetails) {

        log.info("현재 사용자 정보 조회 요청");

        if (userDetails == null) {
            log.debug("UserDetails가 null입니다.");
            return null;
        }

        String username = userDetails.getUsername();

        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UserNotFoundException(username));

        log.debug("조회된 사용자 정보: {}", user);

        return userMapper.toDto(user);
    }
}