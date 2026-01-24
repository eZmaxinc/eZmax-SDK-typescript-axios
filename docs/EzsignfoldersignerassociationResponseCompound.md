# EzsignfoldersignerassociationResponseCompound

An Ezsignfoldersignerassociation Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignfoldersignerassociationID** | **number** | The unique ID of the Ezsignfoldersignerassociation | [default to undefined]
**fkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**bEzsignfoldersignerassociationDelayedsend** | **boolean** | If this flag is true the signatory is part of a delayed send. | [default to undefined]
**bEzsignfoldersignerassociationReceivecopy** | **boolean** | If this flag is true. The signatory will receive a copy of every signed Ezsigndocument even if it ain\&#39;t required to sign the document. | [default to undefined]
**tEzsignfoldersignerassociationMessage** | **string** | A custom text message that will be added to the email sent. | [default to undefined]
**bEzsignfoldersignerassociationAllowsigninginperson** | **boolean** | If the Ezsignfoldersignerassociation is allowed to sign in person or not | [default to undefined]
**objEzsignsignergroup** | [**EzsignsignergroupResponseCompound**](EzsignsignergroupResponseCompound.md) |  | [optional] [default to undefined]
**objUser** | [**EzsignfoldersignerassociationResponseCompoundUser**](EzsignfoldersignerassociationResponseCompoundUser.md) |  | [optional] [default to undefined]
**objEzsignsigner** | [**EzsignsignerResponseCompound**](EzsignsignerResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsignfoldersignerassociationResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfoldersignerassociationResponseCompound = {
    pkiEzsignfoldersignerassociationID,
    fkiEzsignfolderID,
    bEzsignfoldersignerassociationDelayedsend,
    bEzsignfoldersignerassociationReceivecopy,
    tEzsignfoldersignerassociationMessage,
    bEzsignfoldersignerassociationAllowsigninginperson,
    objEzsignsignergroup,
    objUser,
    objEzsignsigner,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
