/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EnumTextvalidation } from './enum-textvalidation';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplateelementdependencyRequestCompound } from './ezsigntemplateelementdependency-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatesignatureRequest } from './ezsigntemplatesignature-request';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatesignaturecustomdateRequestCompoundV2 } from './ezsigntemplatesignaturecustomdate-request-compound-v2';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplatesignatureAttachmentnamesource } from './field-eezsigntemplatesignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplatesignatureConsultationtrigger } from './field-eezsigntemplatesignature-consultationtrigger';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplatesignatureDependencyrequirement } from './field-eezsigntemplatesignature-dependencyrequirement';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplatesignatureFont } from './field-eezsigntemplatesignature-font';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplatesignaturePositioning } from './field-eezsigntemplatesignature-positioning';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplatesignaturePositioningoccurence } from './field-eezsigntemplatesignature-positioningoccurence';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplatesignatureTooltipposition } from './field-eezsigntemplatesignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplatesignatureType } from './field-eezsigntemplatesignature-type';

/**
 * @type EzsigntemplatesignatureRequestCompoundV2
 * A Ezsigntemplatesignature Object and children
 * @export
 */
/*export type EzsigntemplatesignatureRequestCompoundV2 = EzsigntemplatesignatureRequest;*/
export interface EzsigntemplatesignatureRequestCompoundV2 {
    /**
     * The unique ID of the Ezsigntemplatesignature
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    pkiEzsigntemplatesignatureID?:number 
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    fkiEzsigntemplatedocumentID:number 
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    fkiEzsigntemplatesignerID:number 
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    fkiEzsigntemplatesignerIDValidation?:number 
    /**
     * Whether the Ezsigntemplatesignature must be handwritten or not when eEzsigntemplatesignatureType = Signature.
     * @type {boolean}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    bEzsigntemplatesignatureHandwritten?:boolean 
    /**
     * Whether the Ezsigntemplatesignature must include a reason or not when eEzsigntemplatesignatureType = Signature.
     * @type {boolean}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    bEzsigntemplatesignatureReason?:boolean 
    /**
     * 
     * @type {FieldEEzsigntemplatesignaturePositioning}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    eEzsigntemplatesignaturePositioning?:FieldEEzsigntemplatesignaturePositioning 
    /**
     * The page number in the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    iEzsigntemplatedocumentpagePagenumber:number 
    /**
     * The X coordinate (Horizontal) where to put the Ezsigntemplatesignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignature 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    iEzsigntemplatesignatureX?:number 
    /**
     * The Y coordinate (Vertical) where to put the Ezsigntemplatesignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignature 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    iEzsigntemplatesignatureY?:number 
    /**
     * The width of the Ezsigntemplatesignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsigntemplatesignature to have a width of 2 inches, you would use \"200\" for the iEzsigntemplatesignatureWidth.
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    iEzsigntemplatesignatureWidth?:number 
    /**
     * The height of the Ezsigntemplatesignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsigntemplatesignature to have an height of 2 inches, you would use \"200\" for the iEzsigntemplatesignatureHeight.
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    iEzsigntemplatesignatureHeight?:number 
    /**
     * The step when the Ezsigntemplatesigner will be invited to sign
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    iEzsigntemplatesignatureStep:number 
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureType}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    eEzsigntemplatesignatureType:FieldEEzsigntemplatesignatureType 
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureConsultationtrigger}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    eEzsigntemplatesignatureConsultationtrigger?:FieldEEzsigntemplatesignatureConsultationtrigger 
    /**
     * A tooltip that will be presented to Ezsigntemplatesigner about the Ezsigntemplatesignature
     * @type {string}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    tEzsigntemplatesignatureTooltip?:string 
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureTooltipposition}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    eEzsigntemplatesignatureTooltipposition?:FieldEEzsigntemplatesignatureTooltipposition 
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureFont}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    eEzsigntemplatesignatureFont?:FieldEEzsigntemplatesignatureFont 
    /**
     * Whether the Ezsigntemplatesignature is required or not. This field is relevant only with Ezsigntemplatesignature with eEzsigntemplatesignatureType = Attachments.
     * @type {boolean}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    bEzsigntemplatesignatureRequired?:boolean 
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureAttachmentnamesource}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    eEzsigntemplatesignatureAttachmentnamesource?:FieldEEzsigntemplatesignatureAttachmentnamesource 
    /**
     * The description attached to the attachment name added in Ezsigntemplatesignature of eEzsigntemplatesignatureType Attachments
     * @type {string}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    sEzsigntemplatesignatureAttachmentdescription?:string 
    /**
     * The step when the Ezsigntemplatesigner will be invited to validate the Ezsigntemplatesignature of eEzsigntemplatesignatureType Attachments
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    iEzsigntemplatesignatureValidationstep?:number 
    /**
     * The maximum length for the value in the Ezsigntemplatesignature  This can only be set if eEzsigntemplatesignatureType is **FieldText** or **FieldTextarea**
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    iEzsigntemplatesignatureMaxlength?:number 
    /**
     * The default value for the Ezsigntemplatesignature  You can use the codes below and they will be replaced at signature time.    | Code | Description | Example | | ------------------------- | ------------ | ------------ | | {sUserFirstname} | The first name of the contact | John | | {sUserLastname} | The last name of the contact | Doe | | {sUserJobtitle} | The job title | Sales Representative | | {sCompany} | Company name | eZmax Solutions Inc. | | {sEmailAddress} | The email address | email@example.com | | {sPhoneE164} | A phone number in E.164 Format | +15149901516 | | {sPhoneE164Cell} | A phone number in E.164 Format | +15149901516 |
     * @type {string}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    sEzsigntemplatesignatureDefaultvalue?:string 
    /**
     * A regular expression to indicate what values are acceptable for the Ezsigntemplatesignature.  This can only be set if eEzsigntemplatesignatureType is **Text** or **Textarea**
     * @type {string}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    sEzsigntemplatesignatureRegexp?:string 
    /**
     * 
     * @type {EnumTextvalidation}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    eEzsigntemplatesignatureTextvalidation?:EnumTextvalidation 
    /**
     * Description of validation rule. Show by signatory.
     * @type {string}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    sEzsigntemplatesignatureTextvalidationcustommessage?:string 
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureDependencyrequirement}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    eEzsigntemplatesignatureDependencyrequirement?:FieldEEzsigntemplatesignatureDependencyrequirement 
    /**
     * The string pattern to search for the positioning. **This is not a regexp**  This will be required if **eEzsigntemplatesignaturePositioning** is set to **PerCoordinates**
     * @type {string}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    sEzsigntemplatesignaturePositioningpattern?:string 
    /**
     * The offset X  This will be required if **eEzsigntemplatesignaturePositioning** is set to **PerCoordinates**
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    iEzsigntemplatesignaturePositioningoffsetx?:number 
    /**
     * The offset Y  This will be required if **eEzsigntemplatesignaturePositioning** is set to **PerCoordinates**
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    iEzsigntemplatesignaturePositioningoffsety?:number 
    /**
     * 
     * @type {FieldEEzsigntemplatesignaturePositioningoccurence}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    eEzsigntemplatesignaturePositioningoccurence?:FieldEEzsigntemplatesignaturePositioningoccurence 
    /**
     * Whether the Ezsigntemplatesignature has a custom date format or not. (Only possible when eEzsigntemplatesignatureType is **Name** or **Handwritten**)
     * @type {boolean}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    bEzsigntemplatesignatureCustomdate?:boolean 
    /**
     * An array of custom date blocks that will be filled at the time of signature.  Can only be used if bEzsigntemplatesignatureCustomdate is true.  Use an empty array if you don\'t want to have a date at all.
     * @type {Array<EzsigntemplatesignaturecustomdateRequestCompoundV2>}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    a_objEzsigntemplatesignaturecustomdate?:Array<EzsigntemplatesignaturecustomdateRequestCompoundV2> 
    /**
     * 
     * @type {Array<EzsigntemplateelementdependencyRequestCompound>}
     * @memberof EzsigntemplatesignatureRequestCompoundV2
     */
    a_objEzsigntemplateelementdependency?:Array<EzsigntemplateelementdependencyRequestCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatesignatureRequestCompoundV2 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignatureRequestCompoundV2
 */
export class DataObjectEzsigntemplatesignatureRequestCompoundV2 {
    pkiEzsigntemplatesignatureID?:number = undefined
    fkiEzsigntemplatedocumentID:number = 0
    fkiEzsigntemplatesignerID:number = 0
    fkiEzsigntemplatesignerIDValidation?:number = undefined
    bEzsigntemplatesignatureHandwritten?:boolean = undefined
    bEzsigntemplatesignatureReason?:boolean = undefined
    eEzsigntemplatesignaturePositioning?:FieldEEzsigntemplatesignaturePositioning = undefined
    iEzsigntemplatedocumentpagePagenumber:number = 0
    iEzsigntemplatesignatureX?:number = undefined
    iEzsigntemplatesignatureY?:number = undefined
    iEzsigntemplatesignatureWidth?:number = undefined
    iEzsigntemplatesignatureHeight?:number = undefined
    iEzsigntemplatesignatureStep:number = 0
    eEzsigntemplatesignatureType:FieldEEzsigntemplatesignatureType = 'Acknowledgement'
    eEzsigntemplatesignatureConsultationtrigger?:FieldEEzsigntemplatesignatureConsultationtrigger = undefined
    tEzsigntemplatesignatureTooltip?:string = undefined
    eEzsigntemplatesignatureTooltipposition?:FieldEEzsigntemplatesignatureTooltipposition = undefined
    eEzsigntemplatesignatureFont?:FieldEEzsigntemplatesignatureFont = undefined
    bEzsigntemplatesignatureRequired?:boolean = undefined
    eEzsigntemplatesignatureAttachmentnamesource?:FieldEEzsigntemplatesignatureAttachmentnamesource = undefined
    sEzsigntemplatesignatureAttachmentdescription?:string = undefined
    iEzsigntemplatesignatureValidationstep?:number = undefined
    iEzsigntemplatesignatureMaxlength?:number = undefined
    sEzsigntemplatesignatureDefaultvalue?:string = undefined
    sEzsigntemplatesignatureRegexp?:string = undefined
    eEzsigntemplatesignatureTextvalidation?:EnumTextvalidation = undefined
    sEzsigntemplatesignatureTextvalidationcustommessage?:string = undefined
    eEzsigntemplatesignatureDependencyrequirement?:FieldEEzsigntemplatesignatureDependencyrequirement = undefined
    sEzsigntemplatesignaturePositioningpattern?:string = undefined
    iEzsigntemplatesignaturePositioningoffsetx?:number = undefined
    iEzsigntemplatesignaturePositioningoffsety?:number = undefined
    eEzsigntemplatesignaturePositioningoccurence?:FieldEEzsigntemplatesignaturePositioningoccurence = undefined
    bEzsigntemplatesignatureCustomdate?:boolean = undefined
    a_objEzsigntemplatesignaturecustomdate?:Array<EzsigntemplatesignaturecustomdateRequestCompoundV2> = undefined
    a_objEzsigntemplateelementdependency?:Array<EzsigntemplateelementdependencyRequestCompound> = undefined
}

/**
 * @export 
 * A EzsigntemplatesignatureRequestCompoundV2 Validation Object
 * @class ValidationObjectEzsigntemplatesignatureRequestCompoundV2
 */
export class ValidationObjectEzsigntemplatesignatureRequestCompoundV2 {
   pkiEzsigntemplatesignatureID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplatedocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatesignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplatesignerIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   bEzsigntemplatesignatureHandwritten = {
      type: 'boolean',
      required: false
   }
   bEzsigntemplatesignatureReason = {
      type: 'boolean',
      required: false
   }
   eEzsigntemplatesignaturePositioning = {
      type: 'enum',
      allowableValues: ['PerCoordinates','PerPositioningPattern'],
      required: false
   }
   iEzsigntemplatedocumentpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   iEzsigntemplatesignatureX = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsigntemplatesignatureY = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsigntemplatesignatureWidth = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsigntemplatesignatureHeight = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsigntemplatesignatureStep = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   eEzsigntemplatesignatureType = {
      type: 'enum',
      allowableValues: ['Acknowledgement','City','Handwritten','Initials','Name','NameReason','Attachments','FieldText','FieldTextarea','Consultation','Signature'],
      required: true
   }
   eEzsigntemplatesignatureConsultationtrigger = {
      type: 'enum',
      allowableValues: ['Automatic','Manual'],
      required: false
   }
   tEzsigntemplatesignatureTooltip = {
      type: 'string',
      required: false
   }
   eEzsigntemplatesignatureTooltipposition = {
      type: 'enum',
      allowableValues: ['TopLeft','TopCenter','TopRight','MiddleLeft','MiddleRight','BottomLeft','BottomCenter','BottomRight'],
      required: false
   }
   eEzsigntemplatesignatureFont = {
      type: 'enum',
      allowableValues: ['Normal','Cursive'],
      required: false
   }
   bEzsigntemplatesignatureRequired = {
      type: 'boolean',
      required: false
   }
   eEzsigntemplatesignatureAttachmentnamesource = {
      type: 'enum',
      allowableValues: ['Description','Customer','DescriptionCustomer'],
      required: false
   }
   sEzsigntemplatesignatureAttachmentdescription = {
      type: 'string',
      required: false
   }
   iEzsigntemplatesignatureValidationstep = {
      type: 'integer',
      required: false
   }
   iEzsigntemplatesignatureMaxlength = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   sEzsigntemplatesignatureDefaultvalue = {
      type: 'string',
      required: false
   }
   sEzsigntemplatesignatureRegexp = {
      type: 'string',
      pattern: /^\^.*\$$|^$/,
      required: false
   }
   eEzsigntemplatesignatureTextvalidation = {
      type: 'enum',
      allowableValues: ['None','Date (YYYY-MM-DD)','Date (MM/DD/YYYY)','Date (MM/DD/YY)','Date (DD/MM/YYYY)','Date (DD/MM/YY)','Email','Letters','Numbers','Zip','Zip+4','PostalCode','Custom'],
      required: false
   }
   sEzsigntemplatesignatureTextvalidationcustommessage = {
      type: 'string',
      minLength: 0,
      maxLength: 50,
      required: false
   }
   eEzsigntemplatesignatureDependencyrequirement = {
      type: 'enum',
      allowableValues: ['AllOf','AnyOf'],
      required: false
   }
   sEzsigntemplatesignaturePositioningpattern = {
      type: 'string',
      pattern: /^.{0,30}$/,
      required: false
   }
   iEzsigntemplatesignaturePositioningoffsetx = {
      type: 'integer',
      required: false
   }
   iEzsigntemplatesignaturePositioningoffsety = {
      type: 'integer',
      required: false
   }
   eEzsigntemplatesignaturePositioningoccurence = {
      type: 'enum',
      allowableValues: ['All','First','Last'],
      required: false
   }
   bEzsigntemplatesignatureCustomdate = {
      type: 'boolean',
      required: false
   }
   a_objEzsigntemplatesignaturecustomdate = {
      type: 'array',
      required: false
   }
   a_objEzsigntemplateelementdependency = {
      type: 'array',
      required: false
   }
} 


