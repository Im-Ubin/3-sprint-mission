package com.sprint.mission.discodeit.repository;

import com.sprint.mission.discodeit.entity.UserStatus;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.NonNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface UserStatusRepository extends JpaRepository<UserStatus, UUID> {

  @Query("SELECT us FROM UserStatus us JOIN FETCH us.user")
  @NonNull
  List<UserStatus> findAll();

  Optional<UserStatus> findByUserId(UUID userId);

  void deleteByUserId(UUID userId);
}
