FROM quay.io/opsmxpublic/ubi8-jre-11:v1
LABEL name='orca'
LABEL maintainer='info@opsmx.io'
LABEL summary='Red Hat certified Open Enterprise Spinnaker ubi8 container image for orca'
LABEL description='Certified Open Enterprise Spinnaker is an Enterprise grade, Red Hat certified and OpsMx supported release of the popular and critically acclaimed Continuous Delivery platform Spinnaker'
LABEL vendor='OpsMx'

COPY orca-web/build/install/orca /opt/orca
RUN yum -y update-minimal --security --sec-severity=Important --sec-severity=Critical --setopt=tsflags=nodocs
RUN yum -y install java-11-openjdk-headless.x86_64 wget vim curl net-tools nettle
RUN yum -y update
RUN useradd spinnaker
RUN mkdir -p /opt/orca/plugins

#custom plugin zip files adding
ARG CUSTOMPLUGIN_RELEASEVERSION
ENV CUSTOMPLUGIN_RELEASEVERSION=$CUSTOMPLUGIN_RELEASEVERSION
RUN wget -O Opsmx.VerificationGatePlugin-VerificationPlugin-v1.0.1-SNAPSHOT.zip -c https://github.com/OpsMx/Customplugins/releases/download/${CUSTOMPLUGIN_RELEASEVERSION}/VerificationPlugin-v1.0.1-SNAPSHOT.zip -P /opt/orca/plugins \
    && wget -O Opsmx.TestVerificationGatePlugin-TestVerificationPlugin-v1.0.1-SNAPSHOT.zip -c https://github.com/OpsMx/Customplugins/releases/download/${CUSTOMPLUGIN_RELEASEVERSION}/TestVerificationPlugin-v1.0.1-SNAPSHOT.zip -P /opt/orca/plugins \
    && wget -O Opsmx.PolicyGatePlugin-policyPlugin-v1.0.1-SNAPSHOT.zip -c https://github.com/OpsMx/Customplugins/releases/download/${CUSTOMPLUGIN_RELEASEVERSION}/policyPlugin-v1.0.1-SNAPSHOT.zip -P /opt/orca/plugins \
    && wget -O Opsmx.PolicyGatePlugin-RbacPlugin-v1.0.1-SNAPSHOT.zip -c https://github.com/OpsMx/Customplugins/releases/download/${CUSTOMPLUGIN_RELEASEVERSION}/RbacPlugin-v1.0.1-SNAPSHOT.zip -P /opt/orca/plugins \    
    && wget -O Opsmx.VisibilityApprovalPlugin-ApprovalStagePlugin-v1.0.1-SNAPSHOT.zip -c https://github.com/OpsMx/Customplugins/releases/download/${CUSTOMPLUGIN_RELEASEVERSION}/ApprovalStagePlugin-v1.0.1-SNAPSHOT.zip -P /opt/orca/plugins
RUN mv Opsmx.VerificationGatePlugin-VerificationPlugin-v1.0.1-SNAPSHOT.zip /opt/orca/plugins/ \
    && mv Opsmx.TestVerificationGatePlugin-TestVerificationPlugin-v1.0.1-SNAPSHOT.zip /opt/orca/plugins/ \
    && mv Opsmx.PolicyGatePlugin-policyPlugin-v1.0.1-SNAPSHOT.zip /opt/orca/plugins/ \
    && mv Opsmx.PolicyGatePlugin-RbacPlugin-v1.0.1-SNAPSHOT.zip /opt/orca/plugins/ \
    && mv Opsmx.VisibilityApprovalPlugin-ApprovalStagePlugin-v1.0.1-SNAPSHOT.zip /opt/orca/plugins/

RUN chmod -R 777 /opt/orca/plugins/
RUN chown -R spinnaker:spinnaker /opt/
USER spinnaker
CMD ["/opt/orca/bin/orca"]
