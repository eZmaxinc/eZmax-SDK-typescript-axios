# CommunicationRequest

Request for POST /1/object/communication

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCommunicationID** | **number** | The unique ID of the Communication. | [optional] [default to undefined]
**eCommunicationImportance** | [**FieldECommunicationImportance**](FieldECommunicationImportance.md) |  | [optional] [default to undefined]
**eCommunicationType** | [**FieldECommunicationType**](FieldECommunicationType.md) |  | [default to undefined]
**objCommunicationsender** | [**CustomCommunicationsenderRequest**](CustomCommunicationsenderRequest.md) |  | [optional] [default to undefined]
**sCommunicationSubject** | **string** | The subject of the Communication | [optional] [default to undefined]
**tCommunicationBody** | **string** | The Body of the Communication | [default to undefined]
**bCommunicationPrivate** | **boolean** | Whether the Communication is private or not | [default to undefined]
**eCommunicationAttachmenttype** | **string** | How the attachment should be included in the email.   Only used if eCommunicationType is **Email** | [optional] [default to undefined]
**iCommunicationAttachmentlinkexpiration** | **number** | The number of days before the attachment link expired.   Only used if eCommunicationType is **Email** and eCommunicationattachmentType is **Link** | [optional] [default to undefined]
**bCommunicationReadreceipt** | **boolean** | Whether we ask for a read receipt or not. | [optional] [default to undefined]

## Example

```typescript
import { CommunicationRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommunicationRequest = {
    pkiCommunicationID,
    eCommunicationImportance,
    eCommunicationType,
    objCommunicationsender,
    sCommunicationSubject,
    tCommunicationBody,
    bCommunicationPrivate,
    eCommunicationAttachmenttype,
    iCommunicationAttachmentlinkexpiration,
    bCommunicationReadreceipt,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
