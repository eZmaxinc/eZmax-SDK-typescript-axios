# EzsignfoldersignerassociationRequestV2

An Ezsignfoldersignerassociation Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignfoldersignerassociationID** | **number** | The unique ID of the Ezsignfoldersignerassociation | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiEzsignsignergroupID** | **number** | The unique ID of the Ezsignsignergroup | [optional] [default to undefined]
**fkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**eEzsignfoldersignerassociationRole** | [**FieldEEzsignfoldersignerassociationRole**](FieldEEzsignfoldersignerassociationRole.md) |  | [default to undefined]
**tEzsignfoldersignerassociationMessage** | **string** | A custom text message that will be added to the email sent. | [optional] [default to undefined]

## Example

```typescript
import { EzsignfoldersignerassociationRequestV2 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfoldersignerassociationRequestV2 = {
    pkiEzsignfoldersignerassociationID,
    fkiUserID,
    fkiEzsignsignergroupID,
    fkiEzsignfolderID,
    eEzsignfoldersignerassociationRole,
    tEzsignfoldersignerassociationMessage,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
