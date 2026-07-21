# EzsignfoldersignerassociationRequestCompoundV2

An Ezsignfoldersignerassociation Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignfoldersignerassociationID** | **number** | The unique ID of the Ezsignfoldersignerassociation | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiEzsignsignergroupID** | **number** | The unique ID of the Ezsignsignergroup | [optional] [default to undefined]
**fkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**eEzsignfoldersignerassociationRole** | [**FieldEEzsignfoldersignerassociationRole**](FieldEEzsignfoldersignerassociationRole.md) |  | [default to undefined]
**tEzsignfoldersignerassociationMessage** | **string** | A custom text message that will be added to the email sent. | [optional] [default to undefined]
**objEzsignsigner** | [**EzsignsignerRequestCompound**](EzsignsignerRequestCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsignfoldersignerassociationRequestCompoundV2 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfoldersignerassociationRequestCompoundV2 = {
    pkiEzsignfoldersignerassociationID,
    fkiUserID,
    fkiEzsignsignergroupID,
    fkiEzsignfolderID,
    eEzsignfoldersignerassociationRole,
    tEzsignfoldersignerassociationMessage,
    objEzsignsigner,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
