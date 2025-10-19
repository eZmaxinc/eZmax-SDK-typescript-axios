# EzsignsignatureResponse

An Ezsignsignature Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignsignatureID** | **number** | The unique ID of the Ezsignsignature | [default to undefined]
**fkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [default to undefined]
**fkiEzsignfoldersignerassociationID** | **number** | The unique ID of the Ezsignfoldersignerassociation | [default to undefined]
**fkiEzsignsigningreasonID** | **number** | The unique ID of the Ezsignsigningreason | [optional] [default to undefined]
**fkiFontID** | **number** | The unique ID of the Font | [optional] [default to undefined]
**fkiPaymentgatewayID** | **number** | The unique ID of the Paymentgateway | [optional] [default to undefined]
**sCurrencyDescriptionX** | **string** | The description of the Currency in the language of the requester | [optional] [default to undefined]
**dEzsignsignatureCreditcardamount** | **string** | The amount of the Creditcard signature | [optional] [default to undefined]
**sEzsignsignatureCreditcardamountdescription** | **string** | The description of the Creditcard signature | [optional] [default to undefined]
**sEzsignsigningreasonDescriptionX** | **string** | The description of the Ezsignsigningreason in the language of the requester | [optional] [default to undefined]
**iEzsignpagePagenumber** | **number** | The page number in the Ezsigndocument | [default to undefined]
**iEzsignsignatureX** | **number** | The X coordinate (Horizontal) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 2 inches from the left border of the page, you would use \&quot;200\&quot; for the X coordinate. | [default to undefined]
**iEzsignsignatureY** | **number** | The Y coordinate (Vertical) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 3 inches from the top border of the page, you would use \&quot;300\&quot; for the Y coordinate. | [default to undefined]
**iEzsignsignatureHeight** | **number** | The height of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have an height of 2 inches, you would use \&quot;200\&quot; for the iEzsignsignatureHeight. | [optional] [default to undefined]
**iEzsignsignatureWidth** | **number** | The width of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have a width of 2 inches, you would use \&quot;200\&quot; for the iEzsignsignatureWidth. | [optional] [default to undefined]
**iEzsignsignatureStep** | **number** | The step when the Ezsignsigner will be invited to sign | [default to undefined]
**iEzsignsignatureStepadjusted** | **number** | The step when the Ezsignsigner will be invited to sign | [optional] [default to undefined]
**eEzsignsignatureType** | [**FieldEEzsignsignatureType**](FieldEEzsignsignatureType.md) |  | [default to undefined]
**tEzsignsignatureTooltip** | **string** | A tooltip that will be presented to Ezsignsigner about the Ezsignsignature | [optional] [default to undefined]
**eEzsignsignatureTooltipposition** | [**FieldEEzsignsignatureTooltipposition**](FieldEEzsignsignatureTooltipposition.md) |  | [optional] [default to undefined]
**eEzsignsignatureFont** | [**FieldEEzsignsignatureFont**](FieldEEzsignsignatureFont.md) |  | [optional] [default to undefined]
**iEzsignsignatureValidationstep** | **number** | The step when the Ezsignsigner will be invited to validate the Ezsignsignature of eEzsignsignatureType Attachments | [optional] [default to undefined]
**sEzsignsignatureAttachmentdescription** | **string** | The description attached to the attachment name added in Ezsignsignature of eEzsignsignatureType Attachments | [optional] [default to undefined]
**eEzsignsignatureAttachmentnamesource** | [**FieldEEzsignsignatureAttachmentnamesource**](FieldEEzsignsignatureAttachmentnamesource.md) |  | [optional] [default to undefined]
**eEzsignsignatureConsultationtrigger** | [**FieldEEzsignsignatureConsultationtrigger**](FieldEEzsignsignatureConsultationtrigger.md) |  | [optional] [default to undefined]
**bEzsignsignatureHandwritten** | **boolean** | Whether the Ezsignsignature must be handwritten or not when eEzsignsignatureType &#x3D; Signature. | [optional] [default to undefined]
**bEzsignsignatureReason** | **boolean** | Whether the Ezsignsignature must include a reason or not when eEzsignsignatureType &#x3D; Signature. | [optional] [default to undefined]
**bEzsignsignatureRequired** | **boolean** | Whether the Ezsignsignature is required or not. This field is relevant only with Ezsignsignature with eEzsignsignatureType &#x3D; Attachments, Text or Textarea. | [optional] [default to undefined]
**fkiEzsignfoldersignerassociationIDValidation** | **number** | The unique ID of the Ezsignfoldersignerassociation | [optional] [default to undefined]
**dtEzsignsignatureDate** | **string** | The date the Ezsignsignature was signed | [optional] [default to undefined]
**iEzsignsignatureattachmentCount** | **number** | The count of Ezsignsignatureattachment | [optional] [default to undefined]
**sEzsignsignatureDescription** | **string** | The value entered while signing Ezsignsignature of eEzsignsignatureType **City**, **FieldText** and **FieldTextarea** | [optional] [default to undefined]
**iEzsignsignatureMaxlength** | **number** | The maximum length for the value in the Ezsignsignature  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea** | [optional] [default to undefined]
**eEzsignsignatureTextvalidation** | [**EnumTextvalidation**](EnumTextvalidation.md) |  | [optional] [default to undefined]
**sEzsignsignatureTextvalidationcustommessage** | **string** | Description of validation rule. Show by signatory. | [optional] [default to undefined]
**eEzsignsignatureDependencyrequirement** | [**FieldEEzsignsignatureDependencyrequirement**](FieldEEzsignsignatureDependencyrequirement.md) |  | [optional] [default to undefined]
**sEzsignsignatureDefaultvalue** | **string** | The default value for the Ezsignsignature  You can use the codes below and they will be replaced at signature time.    | Code | Description | Example | | ------------------------- | ------------ | ------------ | | {sUserFirstname} | The first name of the contact | John | | {sUserLastname} | The last name of the contact | Doe | | {sUserJobtitle} | The job title | Sales Representative | | {sCompany} | Company name | eZmax Solutions Inc. | | {sEmailAddress} | The email address | email@example.com | | {sPhoneE164} | A phone number in E.164 Format | +15149901516 | | {sPhoneE164Cell} | A phone number in E.164 Format | +15149901516 | | [optional] [default to undefined]
**sEzsignsignatureRegexp** | **string** | A regular expression to indicate what values are acceptable for the Ezsignsignature.  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea** and eEzsignsignatureTextvalidation is **Custom** | [optional] [default to undefined]
**objContactName** | [**CustomContactNameResponse**](CustomContactNameResponse.md) |  | [default to undefined]
**objContactNameDelegation** | [**CustomContactNameResponse**](CustomContactNameResponse.md) |  | [optional] [default to undefined]
**objSignature** | [**SignatureResponseCompound**](SignatureResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsignsignatureResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignsignatureResponse = {
    pkiEzsignsignatureID,
    fkiEzsigndocumentID,
    fkiEzsignfoldersignerassociationID,
    fkiEzsignsigningreasonID,
    fkiFontID,
    fkiPaymentgatewayID,
    sCurrencyDescriptionX,
    dEzsignsignatureCreditcardamount,
    sEzsignsignatureCreditcardamountdescription,
    sEzsignsigningreasonDescriptionX,
    iEzsignpagePagenumber,
    iEzsignsignatureX,
    iEzsignsignatureY,
    iEzsignsignatureHeight,
    iEzsignsignatureWidth,
    iEzsignsignatureStep,
    iEzsignsignatureStepadjusted,
    eEzsignsignatureType,
    tEzsignsignatureTooltip,
    eEzsignsignatureTooltipposition,
    eEzsignsignatureFont,
    iEzsignsignatureValidationstep,
    sEzsignsignatureAttachmentdescription,
    eEzsignsignatureAttachmentnamesource,
    eEzsignsignatureConsultationtrigger,
    bEzsignsignatureHandwritten,
    bEzsignsignatureReason,
    bEzsignsignatureRequired,
    fkiEzsignfoldersignerassociationIDValidation,
    dtEzsignsignatureDate,
    iEzsignsignatureattachmentCount,
    sEzsignsignatureDescription,
    iEzsignsignatureMaxlength,
    eEzsignsignatureTextvalidation,
    sEzsignsignatureTextvalidationcustommessage,
    eEzsignsignatureDependencyrequirement,
    sEzsignsignatureDefaultvalue,
    sEzsignsignatureRegexp,
    objContactName,
    objContactNameDelegation,
    objSignature,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
