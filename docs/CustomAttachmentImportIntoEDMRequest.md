# CustomAttachmentImportIntoEDMRequest

A AttachmentImportIntoEDM object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eAttachmentSource** | **string** | The source of the Attachment | [default to undefined]
**fkiAttachmentID** | **number** | The unique ID of the Attachment. | [optional] [default to undefined]
**fkiInscriptionchecklistID** | **number** | The unique ID of the Inscriptionchecklist | [optional] [default to undefined]
**sAttachmentUrl** | **string** | The url of the file to import | [optional] [default to undefined]
**sAttachmentBase64** | **string** | The Base64 encoded binary content of the attachment. | [optional] [default to undefined]
**sAttachmentName** | **string** | The name of the Attachment | [default to undefined]
**sAttachmentCategory** | **string** | The attachment category | [default to undefined]
**eAttachmentPrivacy** | [**FieldEAttachmentPrivacy**](FieldEAttachmentPrivacy.md) |  | [default to undefined]
**fkiUserIDSpecific** | **number** | The unique ID of the User | [optional] [default to undefined]
**sAttachmentMD5** | **string** | The MD5 of the Attachment | [optional] [default to undefined]
**bAttachmentForceoverwrite** | **boolean** | Whether we force an overwrite of an existing file | [optional] [default to undefined]
**bAttachmentForcerestore** | **boolean** | Whether we force a restore of a deleted file | [optional] [default to undefined]

## Example

```typescript
import { CustomAttachmentImportIntoEDMRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomAttachmentImportIntoEDMRequest = {
    eAttachmentSource,
    fkiAttachmentID,
    fkiInscriptionchecklistID,
    sAttachmentUrl,
    sAttachmentBase64,
    sAttachmentName,
    sAttachmentCategory,
    eAttachmentPrivacy,
    fkiUserIDSpecific,
    sAttachmentMD5,
    bAttachmentForceoverwrite,
    bAttachmentForcerestore,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
