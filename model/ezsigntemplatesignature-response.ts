/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
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
 * A Ezsigntemplatesignature Object
 * @export
 * @interface EzsigntemplatesignatureResponse
 */
export interface EzsigntemplatesignatureResponse {
    /**
     * The unique ID of the Ezsigntemplatesignature
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'pkiEzsigntemplatesignatureID': number;*/
    'pkiEzsigntemplatesignatureID': number;
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'fkiEzsigntemplatedocumentID': number;*/
    'fkiEzsigntemplatedocumentID': number;
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'fkiEzsigntemplatesignerID': number;*/
    'fkiEzsigntemplatesignerID': number;
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'fkiEzsigntemplatesignerIDValidation'?: number;*/
    'fkiEzsigntemplatesignerIDValidation'?: number;
    /**
     * Whether the Ezsigntemplatesignature must be handwritten or not when eEzsigntemplatesignatureType = Signature.
     * @type {boolean}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'bEzsigntemplatesignatureHandwritten'?: boolean;*/
    'bEzsigntemplatesignatureHandwritten'?: boolean;
    /**
     * Whether the Ezsigntemplatesignature must include a reason or not when eEzsigntemplatesignatureType = Signature.
     * @type {boolean}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'bEzsigntemplatesignatureReason'?: boolean;*/
    'bEzsigntemplatesignatureReason'?: boolean;
    /**
     * 
     * @type {FieldEEzsigntemplatesignaturePositioning}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'eEzsigntemplatesignaturePositioning'?: FieldEEzsigntemplatesignaturePositioning;*/
    'eEzsigntemplatesignaturePositioning'?: FieldEEzsigntemplatesignaturePositioning;
    /**
     * The page number in the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'iEzsigntemplatedocumentpagePagenumber': number;*/
    'iEzsigntemplatedocumentpagePagenumber': number;
    /**
     * The X coordinate (Horizontal) where to put the Ezsigntemplatesignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignature 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'iEzsigntemplatesignatureX'?: number;*/
    'iEzsigntemplatesignatureX'?: number;
    /**
     * The Y coordinate (Vertical) where to put the Ezsigntemplatesignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignature 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'iEzsigntemplatesignatureY'?: number;*/
    'iEzsigntemplatesignatureY'?: number;
    /**
     * The width of the Ezsigntemplatesignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsigntemplatesignature to have a width of 2 inches, you would use \"200\" for the iEzsigntemplatesignatureWidth.
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'iEzsigntemplatesignatureWidth'?: number;*/
    'iEzsigntemplatesignatureWidth'?: number;
    /**
     * The height of the Ezsigntemplatesignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsigntemplatesignature to have an height of 2 inches, you would use \"200\" for the iEzsigntemplatesignatureHeight.
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'iEzsigntemplatesignatureHeight'?: number;*/
    'iEzsigntemplatesignatureHeight'?: number;
    /**
     * The step when the Ezsigntemplatesigner will be invited to sign
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'iEzsigntemplatesignatureStep': number;*/
    'iEzsigntemplatesignatureStep': number;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureType}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'eEzsigntemplatesignatureType': FieldEEzsigntemplatesignatureType;*/
    'eEzsigntemplatesignatureType': FieldEEzsigntemplatesignatureType;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureConsultationtrigger}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'eEzsigntemplatesignatureConsultationtrigger'?: FieldEEzsigntemplatesignatureConsultationtrigger;*/
    'eEzsigntemplatesignatureConsultationtrigger'?: FieldEEzsigntemplatesignatureConsultationtrigger;
    /**
     * A tooltip that will be presented to Ezsigntemplatesigner about the Ezsigntemplatesignature
     * @type {string}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'tEzsigntemplatesignatureTooltip'?: string;*/
    'tEzsigntemplatesignatureTooltip'?: string;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureTooltipposition}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'eEzsigntemplatesignatureTooltipposition'?: FieldEEzsigntemplatesignatureTooltipposition;*/
    'eEzsigntemplatesignatureTooltipposition'?: FieldEEzsigntemplatesignatureTooltipposition;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureFont}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'eEzsigntemplatesignatureFont'?: FieldEEzsigntemplatesignatureFont;*/
    'eEzsigntemplatesignatureFont'?: FieldEEzsigntemplatesignatureFont;
    /**
     * The step when the Ezsigntemplatesigner will be invited to validate the Ezsigntemplatesignature of eEzsigntemplatesignatureType Attachments
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'iEzsigntemplatesignatureValidationstep'?: number;*/
    'iEzsigntemplatesignatureValidationstep'?: number;
    /**
     * The description attached to the attachment name added in Ezsigntemplatesignature of eEzsigntemplatesignatureType Attachments
     * @type {string}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'sEzsigntemplatesignatureAttachmentdescription'?: string;*/
    'sEzsigntemplatesignatureAttachmentdescription'?: string;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureAttachmentnamesource}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'eEzsigntemplatesignatureAttachmentnamesource'?: FieldEEzsigntemplatesignatureAttachmentnamesource;*/
    'eEzsigntemplatesignatureAttachmentnamesource'?: FieldEEzsigntemplatesignatureAttachmentnamesource;
    /**
     * Whether the Ezsigntemplatesignature is required or not. This field is relevant only with Ezsigntemplatesignature with eEzsigntemplatesignatureType = Attachments.
     * @type {boolean}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'bEzsigntemplatesignatureRequired'?: boolean;*/
    'bEzsigntemplatesignatureRequired'?: boolean;
    /**
     * The maximum length for the value in the Ezsigntemplatesignature  This can only be set if eEzsigntemplatesignatureType is **FieldText** or **FieldTextarea**
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'iEzsigntemplatesignatureMaxlength'?: number;*/
    'iEzsigntemplatesignatureMaxlength'?: number;
    /**
     * The default value for the Ezsigntemplatesignature  You can use the codes below and they will be replaced at signature time.    | Code | Description | Example | | ------------------------- | ------------ | ------------ | | {sUserFirstname} | The first name of the contact | John | | {sUserLastname} | The last name of the contact | Doe | | {sUserJobtitle} | The job title | Sales Representative | | {sCompany} | Company name | eZmax Solutions Inc. | | {sEmailAddress} | The email address | email@example.com | | {sPhoneE164} | A phone number in E.164 Format | +15149901516 | | {sPhoneE164Cell} | A phone number in E.164 Format | +15149901516 |
     * @type {string}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'sEzsigntemplatesignatureDefaultvalue'?: string;*/
    'sEzsigntemplatesignatureDefaultvalue'?: string;
    /**
     * A regular expression to indicate what values are acceptable for the Ezsigntemplatesignature.  This can only be set if eEzsigntemplatesignatureType is **Text** or **Textarea**
     * @type {string}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'sEzsigntemplatesignatureRegexp'?: string;*/
    'sEzsigntemplatesignatureRegexp'?: string;
    /**
     * 
     * @type {EnumTextvalidation}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'eEzsigntemplatesignatureTextvalidation'?: EnumTextvalidation;*/
    'eEzsigntemplatesignatureTextvalidation'?: EnumTextvalidation;
    /**
     * Description of validation rule. Show by signatory.
     * @type {string}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'sEzsigntemplatesignatureTextvalidationcustommessage'?: string;*/
    'sEzsigntemplatesignatureTextvalidationcustommessage'?: string;
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureDependencyrequirement}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'eEzsigntemplatesignatureDependencyrequirement'?: FieldEEzsigntemplatesignatureDependencyrequirement;*/
    'eEzsigntemplatesignatureDependencyrequirement'?: FieldEEzsigntemplatesignatureDependencyrequirement;
    /**
     * The string pattern to search for the positioning. **This is not a regexp**  This will be required if **eEzsigntemplatesignaturePositioning** is set to **PerCoordinates**
     * @type {string}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'sEzsigntemplatesignaturePositioningpattern'?: string;*/
    'sEzsigntemplatesignaturePositioningpattern'?: string;
    /**
     * The offset X  This will be required if **eEzsigntemplatesignaturePositioning** is set to **PerCoordinates**
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'iEzsigntemplatesignaturePositioningoffsetx'?: number;*/
    'iEzsigntemplatesignaturePositioningoffsetx'?: number;
    /**
     * The offset Y  This will be required if **eEzsigntemplatesignaturePositioning** is set to **PerCoordinates**
     * @type {number}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'iEzsigntemplatesignaturePositioningoffsety'?: number;*/
    'iEzsigntemplatesignaturePositioningoffsety'?: number;
    /**
     * 
     * @type {FieldEEzsigntemplatesignaturePositioningoccurence}
     * @memberof EzsigntemplatesignatureResponse
     */
    /*'eEzsigntemplatesignaturePositioningoccurence'?: FieldEEzsigntemplatesignaturePositioningoccurence;*/
    'eEzsigntemplatesignaturePositioningoccurence'?: FieldEEzsigntemplatesignaturePositioningoccurence;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatesignatureResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignatureResponse
 */
export class DataObjectEzsigntemplatesignatureResponse {
   pkiEzsigntemplatesignatureID:number = 0
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
   iEzsigntemplatesignatureValidationstep?:number = undefined
   sEzsigntemplatesignatureAttachmentdescription?:string = undefined
   eEzsigntemplatesignatureAttachmentnamesource?:FieldEEzsigntemplatesignatureAttachmentnamesource = undefined
   bEzsigntemplatesignatureRequired?:boolean = undefined
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
}

/**
 * @export 
 * A EzsigntemplatesignatureResponse Validation Object
 * @class ValidationObjectEzsigntemplatesignatureResponse
 */
export class ValidationObjectEzsigntemplatesignatureResponse {
   pkiEzsigntemplatesignatureID = {
      type: 'integer',
      minimum: 0,
      required: true
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
      allowableValues: ['Acknowledgement','Attachments','City','Consultation','Creditcard','FieldText','FieldTextarea','Handwritten','Initials','Name','NameReason','Signature'],
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
   iEzsigntemplatesignatureValidationstep = {
      type: 'integer',
      required: false
   }
   sEzsigntemplatesignatureAttachmentdescription = {
      type: 'string',
      required: false
   }
   eEzsigntemplatesignatureAttachmentnamesource = {
      type: 'enum',
      allowableValues: ['Description','Customer','DescriptionCustomer'],
      required: false
   }
   bEzsigntemplatesignatureRequired = {
      type: 'boolean',
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
} 


