# EzsignsignatureRequestCompound

An Ezsignsignature Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignsignatureID** | **number** | The unique ID of the Ezsignsignature | [optional] [default to undefined]
**fkiEzsignfoldersignerassociationID** | **number** | The unique ID of the Ezsignfoldersignerassociation | [default to undefined]
**fkiPaymentgatewayID** | **number** | The unique ID of the Paymentgateway | [optional] [default to undefined]
**iEzsignpagePagenumber** | **number** | The page number in the Ezsigndocument | [default to undefined]
**iEzsignsignatureX** | **number** | The X coordinate (Horizontal) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 2 inches from the left border of the page, you would use \&quot;200\&quot; for the X coordinate. | [default to undefined]
**iEzsignsignatureY** | **number** | The Y coordinate (Vertical) where to put the Ezsignsignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignsignature 3 inches from the top border of the page, you would use \&quot;300\&quot; for the Y coordinate. | [default to undefined]
**iEzsignsignatureWidth** | **number** | The width of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have a width of 2 inches, you would use \&quot;200\&quot; for the iEzsignsignatureWidth. | [optional] [default to undefined]
**iEzsignsignatureHeight** | **number** | The height of the Ezsignsignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsignsignature to have an height of 2 inches, you would use \&quot;200\&quot; for the iEzsignsignatureHeight. | [optional] [default to undefined]
**iEzsignsignatureStep** | **number** | The step when the Ezsignsigner will be invited to sign | [default to undefined]
**eEzsignsignatureType** | [**FieldEEzsignsignatureType**](FieldEEzsignsignatureType.md) |  | [default to undefined]
**eEzsignsignatureSignaturepad** | [**FieldEEzsignsignatureSignaturepad**](FieldEEzsignsignatureSignaturepad.md) |  | [optional] [default to undefined]
**eEzsignsignatureSignaturepadrequired** | [**FieldEEzsignsignatureSignaturepadrequired**](FieldEEzsignsignatureSignaturepadrequired.md) |  | [optional] [default to undefined]
**fkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [default to undefined]
**tEzsignsignatureTooltip** | **string** | A tooltip that will be presented to Ezsignsigner about the Ezsignsignature | [optional] [default to undefined]
**eEzsignsignatureTooltipposition** | [**FieldEEzsignsignatureTooltipposition**](FieldEEzsignsignatureTooltipposition.md) |  | [optional] [default to undefined]
**eEzsignsignatureFont** | [**FieldEEzsignsignatureFont**](FieldEEzsignsignatureFont.md) |  | [optional] [default to undefined]
**fkiEzsignfoldersignerassociationIDValidation** | **number** | The unique ID of the Ezsignfoldersignerassociation | [optional] [default to undefined]
**bEzsignsignatureHandwritten** | **boolean** | Whether the Ezsignsignature must be handwritten or not when eEzsignsignatureType &#x3D; Signature. | [optional] [default to undefined]
**bEzsignsignatureReason** | **boolean** | Whether the Ezsignsignature must include a reason or not when eEzsignsignatureType &#x3D; Signature. | [optional] [default to undefined]
**bEzsignsignatureRequired** | **boolean** | Whether the Ezsignsignature is required or not. This field is relevant only with Ezsignsignature with eEzsignsignatureType &#x3D; Attachments, Text or Textarea. | [optional] [default to undefined]
**eEzsignsignatureAttachmentnamesource** | [**FieldEEzsignsignatureAttachmentnamesource**](FieldEEzsignsignatureAttachmentnamesource.md) |  | [optional] [default to undefined]
**sEzsignsignatureAttachmentdescription** | **string** | The description attached to the attachment name added in Ezsignsignature of eEzsignsignatureType Attachments | [optional] [default to undefined]
**eEzsignsignatureConsultationtrigger** | [**FieldEEzsignsignatureConsultationtrigger**](FieldEEzsignsignatureConsultationtrigger.md) |  | [optional] [default to undefined]
**iEzsignsignatureValidationstep** | **number** | The step when the Ezsignsigner will be invited to validate the Ezsignsignature of eEzsignsignatureType Attachments | [optional] [default to undefined]
**iEzsignsignatureMaxlength** | **number** | The maximum length for the value in the Ezsignsignature  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea** | [optional] [default to undefined]
**sEzsignsignatureDefaultvalue** | **string** | The default value for the Ezsignsignature  You can use the codes below and they will be replaced at signature time.    | Code | Description | Example | | ------------------------- | ------------ | ------------ | | {sUserFirstname} | The first name of the contact | John | | {sUserLastname} | The last name of the contact | Doe | | {sUserJobtitle} | The job title | Sales Representative | | {sCompany} | Company name | eZmax Solutions Inc. | | {sEmailAddress} | The email address | email@example.com | | {sPhoneE164} | A phone number in E.164 Format | +15149901516 | | {sPhoneE164Cell} | A phone number in E.164 Format | +15149901516 | | [optional] [default to undefined]
**eEzsignsignatureTextvalidation** | [**EnumTextvalidation**](EnumTextvalidation.md) |  | [optional] [default to undefined]
**sEzsignsignatureTextvalidationcustommessage** | **string** | Description of validation rule. Show by signatory. | [optional] [default to undefined]
**sEzsignsignatureRegexp** | **string** | A regular expression to indicate what values are acceptable for the Ezsignsignature.  This can only be set if eEzsignsignatureType is **FieldText** or **FieldTextarea** and eEzsignsignatureTextvalidation is **Custom** | [optional] [default to undefined]
**eEzsignsignatureDependencyrequirement** | [**FieldEEzsignsignatureDependencyrequirement**](FieldEEzsignsignatureDependencyrequirement.md) |  | [optional] [default to undefined]
**sEzsignsignatureCreditcardamountdescription** | **string** | The description of the Creditcard signature | [optional] [default to undefined]
**dEzsignsignatureCreditcardamount** | **string** | The amount of the Creditcard signature | [optional] [default to undefined]
**bEzsignsignatureCreditcardcustomamount** | **boolean** | Whether we can enter a custom amount while signing an Ezsignsignature \&#39;Creditcard\&#39; or not | [optional] [default to undefined]
**bEzsignsignatureCustomdate** | **boolean** | Whether the Ezsignsignature has a custom date format or not. (Only possible when eEzsignsignatureType is **Name** or **Handwritten**) | [optional] [default to undefined]
**a_objEzsignsignaturecustomdate** | [**Array&lt;EzsignsignaturecustomdateRequestCompound&gt;**](EzsignsignaturecustomdateRequestCompound.md) | An array of custom date blocks that will be filled at the time of signature.  Can only be used if bEzsignsignatureCustomdate is true.  Use an empty array if you don\&#39;t want to have a date at all. | [optional] [default to undefined]
**a_objEzsignelementdependency** | [**Array&lt;EzsignelementdependencyRequestCompound&gt;**](EzsignelementdependencyRequestCompound.md) |  | [optional] [default to undefined]
**a_objEzsignsignaturepaymentdetail** | [**Array&lt;EzsignsignaturepaymentdetailRequestCompound&gt;**](EzsignsignaturepaymentdetailRequestCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsignsignatureRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignsignatureRequestCompound = {
    pkiEzsignsignatureID,
    fkiEzsignfoldersignerassociationID,
    fkiPaymentgatewayID,
    iEzsignpagePagenumber,
    iEzsignsignatureX,
    iEzsignsignatureY,
    iEzsignsignatureWidth,
    iEzsignsignatureHeight,
    iEzsignsignatureStep,
    eEzsignsignatureType,
    eEzsignsignatureSignaturepad,
    eEzsignsignatureSignaturepadrequired,
    fkiEzsigndocumentID,
    tEzsignsignatureTooltip,
    eEzsignsignatureTooltipposition,
    eEzsignsignatureFont,
    fkiEzsignfoldersignerassociationIDValidation,
    bEzsignsignatureHandwritten,
    bEzsignsignatureReason,
    bEzsignsignatureRequired,
    eEzsignsignatureAttachmentnamesource,
    sEzsignsignatureAttachmentdescription,
    eEzsignsignatureConsultationtrigger,
    iEzsignsignatureValidationstep,
    iEzsignsignatureMaxlength,
    sEzsignsignatureDefaultvalue,
    eEzsignsignatureTextvalidation,
    sEzsignsignatureTextvalidationcustommessage,
    sEzsignsignatureRegexp,
    eEzsignsignatureDependencyrequirement,
    sEzsignsignatureCreditcardamountdescription,
    dEzsignsignatureCreditcardamount,
    bEzsignsignatureCreditcardcustomamount,
    bEzsignsignatureCustomdate,
    a_objEzsignsignaturecustomdate,
    a_objEzsignelementdependency,
    a_objEzsignsignaturepaymentdetail,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
