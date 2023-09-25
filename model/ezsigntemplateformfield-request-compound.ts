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
import { EzsigntemplateformfieldRequest } from './ezsigntemplateformfield-request';

/**
 * @type EzsigntemplateformfieldRequestCompound
 * An Ezsigntemplateformfield Object and children to create a complete structure
 * @export
 */
/** export type EzsigntemplateformfieldRequestCompound = EzsigntemplateformfieldRequest; */
export interface EzsigntemplateformfieldRequestCompound {
    /**
     * The unique ID of the Ezsigntemplateformfield
     * @type {number}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    pkiEzsigntemplateformfieldID?:number 
    /**
     * The page number in the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    iEzsigntemplatedocumentpagePagenumber:number 
    /**
     * The Label for the Ezsigntemplateformfield
     * @type {string}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    sEzsigntemplateformfieldLabel:string 
    /**
     * The value for the Ezsigntemplateformfield
     * @type {string}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    sEzsigntemplateformfieldValue?:string 
    /**
     * The X coordinate (Horizontal) where to put the Ezsigntemplateformfield on the Ezsigntemplatepage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplateformfield 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    iEzsigntemplateformfieldX:number 
    /**
     * The Y coordinate (Vertical) where to put the Ezsigntemplateformfield on the Ezsigntemplatepage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplateformfield 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    iEzsigntemplateformfieldY:number 
    /**
     * The Width of the Ezsigntemplateformfield in pixels calculated at 100 DPI  The allowed values are varying based on the eEzsigntemplateformfieldgroupType.  | eEzsigntemplateformfieldgroupType | Valid values | | ------------------------- | ------------ | | Checkbox                  | 22           | | Dropdown                  | 22-65535     | | Radio                     | 22           | | Text                      | 22-65535     | | Textarea                  | 22-65535     |
     * @type {number}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    iEzsigntemplateformfieldWidth:number 
    /**
     * The Height of the Ezsigntemplateformfield in pixels calculated at 100 DPI  The allowed values are varying based on the eEzsigntemplateformfieldgroupType.  | eEzsigntemplateformfieldgroupType | Valid values | | ------------------------- | ------------ | | Checkbox                  | 22           | | Dropdown                  | 22           | | Radio                     | 22           | | Text                      | 22           | | Textarea                  | 22-65535     | 
     * @type {number}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    iEzsigntemplateformfieldHeight:number 
    /**
     * Whether the Ezsigntemplateformfield is selected or not by default.  This can only be set if eEzsigntemplateformfieldgroupType is **Checkbox** or **Radio**
     * @type {boolean}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    bEzsigntemplateformfieldSelected?:boolean 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateformfieldRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateformfieldRequestCompound
 */
export class DataObjectEzsigntemplateformfieldRequestCompound {
    pkiEzsigntemplateformfieldID?:number = undefined
    iEzsigntemplatedocumentpagePagenumber:number = 0
    sEzsigntemplateformfieldLabel:string = ''
    sEzsigntemplateformfieldValue?:string = undefined
    iEzsigntemplateformfieldX:number = 0
    iEzsigntemplateformfieldY:number = 0
    iEzsigntemplateformfieldWidth:number = 0
    iEzsigntemplateformfieldHeight:number = 0
    bEzsigntemplateformfieldSelected?:boolean = undefined
}

/**
 * @export 
 * A EzsigntemplateformfieldRequestCompound Validation Object
 * @class ValidationObjectEzsigntemplateformfieldRequestCompound
 */
export class ValidationObjectEzsigntemplateformfieldRequestCompound {
   pkiEzsigntemplateformfieldID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsigntemplatedocumentpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sEzsigntemplateformfieldLabel = {
      type: 'string',
      required: true
   }
   sEzsigntemplateformfieldValue = {
      type: 'string',
      required: false
   }
   iEzsigntemplateformfieldX = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplateformfieldY = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplateformfieldWidth = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsigntemplateformfieldHeight = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzsigntemplateformfieldSelected = {
      type: 'boolean',
      required: false
   }
} 


