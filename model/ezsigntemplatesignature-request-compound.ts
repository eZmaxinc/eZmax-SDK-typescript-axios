/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EnumTextvalidation } from './enum-textvalidation';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateelementdependencyRequestCompound } from './ezsigntemplateelementdependency-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignatureRequest } from './ezsigntemplatesignature-request';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignaturecustomdateRequestCompound } from './ezsigntemplatesignaturecustomdate-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureAttachmentnamesource } from './field-eezsigntemplatesignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureDependencyrequirement } from './field-eezsigntemplatesignature-dependencyrequirement';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureFont } from './field-eezsigntemplatesignature-font';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignaturePositioning } from './field-eezsigntemplatesignature-positioning';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignaturePositioningoccurence } from './field-eezsigntemplatesignature-positioningoccurence';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureTooltipposition } from './field-eezsigntemplatesignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureType } from './field-eezsigntemplatesignature-type';

/**
 * @type EzsigntemplatesignatureRequestCompound
 * A Ezsigntemplatesignature Object and children
 * @export
 */
/*export type EzsigntemplatesignatureRequestCompound = EzsigntemplatesignatureRequest;*/
export interface EzsigntemplatesignatureRequestCompound {
    /**
     * The unique ID of the Ezsigntemplatesignature
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    pkiEzsigntemplatesignatureID?:number 
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    fkiEzsigntemplatedocumentID:number 
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    fkiEzsigntemplatesignerID:number 
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    fkiEzsigntemplatesignerIDValidation?:number 
    /**
     * 
     * @type {FieldEEzsigntemplatesignaturePositioning}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    eEzsigntemplatesignaturePositioning?:FieldEEzsigntemplatesignaturePositioning 
    /**
     * The page number in the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    iEzsigntemplatedocumentpagePagenumber:number 
    /**
     * The X coordinate (Horizontal) where to put the Ezsigntemplatesignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignature 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    iEzsigntemplatesignatureX?:number 
    /**
     * The Y coordinate (Vertical) where to put the Ezsigntemplatesignature on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplatesignature 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    iEzsigntemplatesignatureY?:number 
    /**
     * The width of the Ezsigntemplatesignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsigntemplatesignature to have a width of 2 inches, you would use \"200\" for the iEzsigntemplatesignatureWidth.
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    iEzsigntemplatesignatureWidth?:number 
    /**
     * The height of the Ezsigntemplatesignature.  Size is calculated at 100dpi (dot per inch). So for example, if you want the Ezsigntemplatesignature to have an height of 2 inches, you would use \"200\" for the iEzsigntemplatesignatureHeight.
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    iEzsigntemplatesignatureHeight?:number 
    /**
     * The step when the Ezsigntemplatesigner will be invited to sign
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    iEzsigntemplatesignatureStep:number 
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureType}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    eEzsigntemplatesignatureType:FieldEEzsigntemplatesignatureType 
    /**
     * A tooltip that will be presented to Ezsigntemplatesigner about the Ezsigntemplatesignature
     * @type {string}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    tEzsigntemplatesignatureTooltip?:string 
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureTooltipposition}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    eEzsigntemplatesignatureTooltipposition?:FieldEEzsigntemplatesignatureTooltipposition 
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureFont}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    eEzsigntemplatesignatureFont?:FieldEEzsigntemplatesignatureFont 
    /**
     * Whether the Ezsigntemplatesignature is required or not. This field is relevant only with Ezsigntemplatesignature with eEzsigntemplatesignatureType = Attachments.
     * @type {boolean}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    bEzsigntemplatesignatureRequired?:boolean 
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureAttachmentnamesource}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    eEzsigntemplatesignatureAttachmentnamesource?:FieldEEzsigntemplatesignatureAttachmentnamesource 
    /**
     * The description attached to the attachment name added in Ezsigntemplatesignature of eEzsigntemplatesignatureType Attachments
     * @type {string}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    sEzsigntemplatesignatureAttachmentdescription?:string 
    /**
     * The step when the Ezsigntemplatesigner will be invited to validate the Ezsigntemplatesignature of eEzsigntemplatesignatureType Attachments
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    iEzsigntemplatesignatureValidationstep?:number 
    /**
     * The maximum length for the value in the Ezsigntemplatesignature  This can only be set if eEzsigntemplatesignatureType is **FieldText** or **FieldTextarea**
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    iEzsigntemplatesignatureMaxlength?:number 
    /**
     * A regular expression to indicate what values are acceptable for the Ezsigntemplatesignature.  This can only be set if eEzsigntemplatesignatureType is **Text** or **Textarea**
     * @type {string}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    sEzsigntemplatesignatureRegexp?:string 
    /**
     * 
     * @type {EnumTextvalidation}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    eEzsigntemplatesignatureTextvalidation?:EnumTextvalidation 
    /**
     * 
     * @type {FieldEEzsigntemplatesignatureDependencyrequirement}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    eEzsigntemplatesignatureDependencyrequirement?:FieldEEzsigntemplatesignatureDependencyrequirement 
    /**
     * The string pattern to search for the positioning. **This is not a regexp**  This will be required if **eEzsigntemplatesignaturePositioning** is set to **PerCoordinates**
     * @type {string}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    sEzsigntemplatesignaturePositioningpattern?:string 
    /**
     * The offset X  This will be required if **eEzsigntemplatesignaturePositioning** is set to **PerCoordinates**
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    iEzsigntemplatesignaturePositioningoffsetx?:number 
    /**
     * The offset Y  This will be required if **eEzsigntemplatesignaturePositioning** is set to **PerCoordinates**
     * @type {number}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    iEzsigntemplatesignaturePositioningoffsety?:number 
    /**
     * 
     * @type {FieldEEzsigntemplatesignaturePositioningoccurence}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    eEzsigntemplatesignaturePositioningoccurence?:FieldEEzsigntemplatesignaturePositioningoccurence 
    /**
     * Whether the Ezsigntemplatesignature has a custom date format or not. (Only possible when eEzsigntemplatesignatureType is **Name** or **Handwritten**)
     * @type {boolean}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    bEzsigntemplatesignatureCustomdate?:boolean 
    /**
     * An array of custom date blocks that will be filled at the time of signature.  Can only be used if bEzsigntemplatesignatureCustomdate is true.  Use an empty array if you don\'t want to have a date at all.
     * @type {Array<EzsigntemplatesignaturecustomdateRequestCompound>}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    a_objEzsigntemplatesignaturecustomdate?:Array<EzsigntemplatesignaturecustomdateRequestCompound> 
    /**
     * 
     * @type {Array<EzsigntemplateelementdependencyRequestCompound>}
     * @memberof EzsigntemplatesignatureRequestCompound
     */
    a_objEzsigntemplateelementdependency?:Array<EzsigntemplateelementdependencyRequestCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatesignatureRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignatureRequestCompound
 */
export class DataObjectEzsigntemplatesignatureRequestCompound {
    pkiEzsigntemplatesignatureID?:number = undefined
    fkiEzsigntemplatedocumentID:number = 0
    fkiEzsigntemplatesignerID:number = 0
    fkiEzsigntemplatesignerIDValidation?:number = undefined
    eEzsigntemplatesignaturePositioning?:FieldEEzsigntemplatesignaturePositioning = undefined
    iEzsigntemplatedocumentpagePagenumber:number = 0
    iEzsigntemplatesignatureX?:number = undefined
    iEzsigntemplatesignatureY?:number = undefined
    iEzsigntemplatesignatureWidth?:number = undefined
    iEzsigntemplatesignatureHeight?:number = undefined
    iEzsigntemplatesignatureStep:number = 0
    eEzsigntemplatesignatureType:FieldEEzsigntemplatesignatureType = 'Acknowledgement'
    tEzsigntemplatesignatureTooltip?:string = undefined
    eEzsigntemplatesignatureTooltipposition?:FieldEEzsigntemplatesignatureTooltipposition = undefined
    eEzsigntemplatesignatureFont?:FieldEEzsigntemplatesignatureFont = undefined
    bEzsigntemplatesignatureRequired?:boolean = undefined
    eEzsigntemplatesignatureAttachmentnamesource?:FieldEEzsigntemplatesignatureAttachmentnamesource = undefined
    sEzsigntemplatesignatureAttachmentdescription?:string = undefined
    iEzsigntemplatesignatureValidationstep?:number = undefined
    iEzsigntemplatesignatureMaxlength?:number = undefined
    sEzsigntemplatesignatureRegexp?:string = undefined
    eEzsigntemplatesignatureTextvalidation?:EnumTextvalidation = undefined
    eEzsigntemplatesignatureDependencyrequirement?:FieldEEzsigntemplatesignatureDependencyrequirement = undefined
    sEzsigntemplatesignaturePositioningpattern?:string = undefined
    iEzsigntemplatesignaturePositioningoffsetx?:number = undefined
    iEzsigntemplatesignaturePositioningoffsety?:number = undefined
    eEzsigntemplatesignaturePositioningoccurence?:FieldEEzsigntemplatesignaturePositioningoccurence = undefined
    bEzsigntemplatesignatureCustomdate?:boolean = undefined
    a_objEzsigntemplatesignaturecustomdate?:Array<EzsigntemplatesignaturecustomdateRequestCompound> = undefined
    a_objEzsigntemplateelementdependency?:Array<EzsigntemplateelementdependencyRequestCompound> = undefined
}

/**
 * @export 
 * A EzsigntemplatesignatureRequestCompound Validation Object
 * @class ValidationObjectEzsigntemplatesignatureRequestCompound
 */
export class ValidationObjectEzsigntemplatesignatureRequestCompound {
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
      allowableValues: ['Acknowledgement','City','Handwritten','Initials','Name','NameReason','Attachments','FieldText','FieldTextarea','Consultation'],
      required: true
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
   sEzsigntemplatesignatureRegexp = {
      type: 'string',
      pattern: '/^\^.*\$$|^$/',
      required: false
   }
   eEzsigntemplatesignatureTextvalidation = {
      type: 'enum',
      allowableValues: ['None','Date (YYYY-MM-DD)','Date (MM/DD/YYYY)','Date (MM/DD/YY)','Date (DD/MM/YYYY)','Date (DD/MM/YY)','Email','Letters','Numbers','Zip','Zip+4','PostalCode','Custom'],
      required: false
   }
   eEzsigntemplatesignatureDependencyrequirement = {
      type: 'enum',
      allowableValues: ['AllOf','AnyOf'],
      required: false
   }
   sEzsigntemplatesignaturePositioningpattern = {
      type: 'string',
      pattern: '/^.{0,30}$/',
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


