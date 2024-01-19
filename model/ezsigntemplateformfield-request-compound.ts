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
import { EzsigntemplateelementdependencyRequestCompound } from './ezsigntemplateelementdependency-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldRequest } from './ezsigntemplateformfield-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateformfieldDependencyrequirement } from './field-eezsigntemplateformfield-dependencyrequirement';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateformfieldPositioning } from './field-eezsigntemplateformfield-positioning';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateformfieldPositioningoccurence } from './field-eezsigntemplateformfield-positioningoccurence';

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
     * 
     * @type {FieldEEzsigntemplateformfieldPositioning}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    eEzsigntemplateformfieldPositioning?:FieldEEzsigntemplateformfieldPositioning 
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
    iEzsigntemplateformfieldX?:number 
    /**
     * The Y coordinate (Vertical) where to put the Ezsigntemplateformfield on the Ezsigntemplatepage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplateformfield 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    iEzsigntemplateformfieldY?:number 
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
     * Whether the Ezsigntemplateformfield allows the use of the autocomplete of the browser.  This can only be set if eEzsigntemplateformfieldgroupType is **Text**
     * @type {boolean}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    bEzsigntemplateformfieldAutocomplete?:boolean 
    /**
     * Whether the Ezsigntemplateformfield is selected or not by default.  This can only be set if eEzsigntemplateformfieldgroupType is **Checkbox** or **Radio**
     * @type {boolean}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    bEzsigntemplateformfieldSelected?:boolean 
    /**
     * 
     * @type {FieldEEzsigntemplateformfieldDependencyrequirement}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    eEzsigntemplateformfieldDependencyrequirement?:FieldEEzsigntemplateformfieldDependencyrequirement 
    /**
     * The string pattern to search for the positioning. **This is not a regexp**  This will be required if **eEzsigntemplateformfieldPositioning** is set to **PerCoordinates**
     * @type {string}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    sEzsigntemplateformfieldPositioningpattern?:string 
    /**
     * The offset X  This will be required if **eEzsigntemplateformfieldPositioning** is set to **PerCoordinates**
     * @type {number}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    iEzsigntemplateformfieldPositioningoffsetx?:number 
    /**
     * The offset Y  This will be required if **eEzsigntemplateformfieldPositioning** is set to **PerCoordinates**
     * @type {number}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    iEzsigntemplateformfieldPositioningoffsety?:number 
    /**
     * 
     * @type {FieldEEzsigntemplateformfieldPositioningoccurence}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    eEzsigntemplateformfieldPositioningoccurence?:FieldEEzsigntemplateformfieldPositioningoccurence 
    /**
     * 
     * @type {Array<EzsigntemplateelementdependencyRequestCompound>}
     * @memberof EzsigntemplateformfieldRequestCompound
     */
    a_objEzsigntemplateelementdependency?:Array<EzsigntemplateelementdependencyRequestCompound> 
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
    eEzsigntemplateformfieldPositioning?:FieldEEzsigntemplateformfieldPositioning = undefined
    iEzsigntemplatedocumentpagePagenumber:number = 0
    sEzsigntemplateformfieldLabel:string = ''
    sEzsigntemplateformfieldValue?:string = undefined
    iEzsigntemplateformfieldX?:number = undefined
    iEzsigntemplateformfieldY?:number = undefined
    iEzsigntemplateformfieldWidth:number = 0
    iEzsigntemplateformfieldHeight:number = 0
    bEzsigntemplateformfieldAutocomplete?:boolean = undefined
    bEzsigntemplateformfieldSelected?:boolean = undefined
    eEzsigntemplateformfieldDependencyrequirement?:FieldEEzsigntemplateformfieldDependencyrequirement = undefined
    sEzsigntemplateformfieldPositioningpattern?:string = undefined
    iEzsigntemplateformfieldPositioningoffsetx?:number = undefined
    iEzsigntemplateformfieldPositioningoffsety?:number = undefined
    eEzsigntemplateformfieldPositioningoccurence?:FieldEEzsigntemplateformfieldPositioningoccurence = undefined
    a_objEzsigntemplateelementdependency?:Array<EzsigntemplateelementdependencyRequestCompound> = undefined
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
   eEzsigntemplateformfieldPositioning = {
      type: 'enum',
      allowableValues: ['PerCoordinates','PerPositioningPattern'],
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
      required: false
   }
   iEzsigntemplateformfieldY = {
      type: 'integer',
      minimum: 0,
      required: false
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
   bEzsigntemplateformfieldAutocomplete = {
      type: 'boolean',
      required: false
   }
   bEzsigntemplateformfieldSelected = {
      type: 'boolean',
      required: false
   }
   eEzsigntemplateformfieldDependencyrequirement = {
      type: 'enum',
      allowableValues: ['AllOf','AnyOf'],
      required: false
   }
   sEzsigntemplateformfieldPositioningpattern = {
      type: 'string',
      pattern: '/^.{0,30}$/',
      required: false
   }
   iEzsigntemplateformfieldPositioningoffsetx = {
      type: 'integer',
      required: false
   }
   iEzsigntemplateformfieldPositioningoffsety = {
      type: 'integer',
      required: false
   }
   eEzsigntemplateformfieldPositioningoccurence = {
      type: 'enum',
      allowableValues: ['All','First','Last'],
      required: false
   }
   a_objEzsigntemplateelementdependency = {
      type: 'array',
      required: false
   }
} 


