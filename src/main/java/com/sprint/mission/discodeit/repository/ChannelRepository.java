package com.sprint.mission.discodeit.repository;

import com.sprint.mission.discodeit.entity.Channel;
import com.sprint.mission.discodeit.entity.ChannelType;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ChannelRepository extends JpaRepository<Channel, UUID> {

  @Query("""
      SELECT DISTINCT c
        FROM Channel c
   LEFT JOIN c.readStatuses rs
       WHERE c.type = :publicType
          OR rs.user.id = :userId
      """)
  List<Channel> findAllAccessible(
      @Param("publicType") ChannelType publicType,
      @Param("userId") UUID userId
  );
}
