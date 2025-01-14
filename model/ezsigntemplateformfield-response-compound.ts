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
import { EnumHorizontalalignment } from './enum-horizontalalignment';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateelementdependencyResponseCompound } from './ezsigntemplateelementdependency-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplateformfieldResponse } from './ezsigntemplateformfield-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateformfieldDependencyrequirement } from './field-eezsigntemplateformfield-dependencyrequirement';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateformfieldPositioning } from './field-eezsigntemplateformfield-positioning';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateformfieldPositioningoccurence } from './field-eezsigntemplateformfield-positioningoccurence';
// May contain unused imports in some cases
// @ts-ignore
import { TextstylestaticResponseCompound } from './textstylestatic-response-compound';

/**
 * @type EzsigntemplateformfieldResponseCompound
 * An Ezsigntemplateformfield Object and children
 * @export
 */
/*export type EzsigntemplateformfieldResponseCompound = EzsigntemplateformfieldResponse;*/
export interface EzsigntemplateformfieldResponseCompound {
    /**
     * The unique ID of the Ezsigntemplateformfield
     * @type {number}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    pkiEzsigntemplateformfieldID:number 
    /**
     * 
     * @type {FieldEEzsigntemplateformfieldPositioning}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    eEzsigntemplateformfieldPositioning?:FieldEEzsigntemplateformfieldPositioning 
    /**
     * The page number in the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    iEzsigntemplatedocumentpagePagenumber:number 
    /**
     * The Label for the Ezsigntemplateformfield
     * @type {string}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    sEzsigntemplateformfieldLabel:string 
    /**
     * The value for the Ezsigntemplateformfield
     * @type {string}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    sEzsigntemplateformfieldValue?:string 
    /**
     * The X coordinate (Horizontal) where to put the Ezsigntemplateformfield on the Ezsigntemplatepage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplateformfield 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    iEzsigntemplateformfieldX?:number 
    /**
     * The Y coordinate (Vertical) where to put the Ezsigntemplateformfield on the Ezsigntemplatepage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsigntemplateformfield 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    iEzsigntemplateformfieldY?:number 
    /**
     * The Width of the Ezsigntemplateformfield in pixels calculated at 100 DPI
     * @type {number}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    iEzsigntemplateformfieldWidth:number 
    /**
     * The Height of the Ezsigntemplateformfield in pixels calculated at 100 DPI 
     * @type {number}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    iEzsigntemplateformfieldHeight:number 
    /**
     * Whether the Ezsigntemplateformfield allows the use of the autocomplete of the browser.  This can only be set if eEzsigntemplateformfieldgroupType is **Text**
     * @type {boolean}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    bEzsigntemplateformfieldAutocomplete?:boolean 
    /**
     * Whether the Ezsigntemplateformfield is selected or not by default.  This can only be set if eEzsigntemplateformfieldgroupType is **Checkbox** or **Radio**
     * @type {boolean}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    bEzsigntemplateformfieldSelected?:boolean 
    /**
     * 
     * @type {FieldEEzsigntemplateformfieldDependencyrequirement}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    eEzsigntemplateformfieldDependencyrequirement?:FieldEEzsigntemplateformfieldDependencyrequirement 
    /**
     * The string pattern to search for the positioning. **This is not a regexp**  This will be required if **eEzsigntemplateformfieldPositioning** is set to **PerCoordinates**
     * @type {string}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    sEzsigntemplateformfieldPositioningpattern?:string 
    /**
     * The offset X  This will be required if **eEzsigntemplateformfieldPositioning** is set to **PerCoordinates**
     * @type {number}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    iEzsigntemplateformfieldPositioningoffsetx?:number 
    /**
     * The offset Y  This will be required if **eEzsigntemplateformfieldPositioning** is set to **PerCoordinates**
     * @type {number}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    iEzsigntemplateformfieldPositioningoffsety?:number 
    /**
     * 
     * @type {FieldEEzsigntemplateformfieldPositioningoccurence}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    eEzsigntemplateformfieldPositioningoccurence?:FieldEEzsigntemplateformfieldPositioningoccurence 
    /**
     * 
     * @type {EnumHorizontalalignment}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    eEzsigntemplateformfieldHorizontalalignment?:EnumHorizontalalignment 
    /**
     * 
     * @type {TextstylestaticResponseCompound}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    objTextstylestatic?:TextstylestaticResponseCompound 
    /**
     * 
     * @type {Array<EzsigntemplateelementdependencyResponseCompound>}
     * @memberof EzsigntemplateformfieldResponseCompound
     */
    a_objEzsigntemplateelementdependency?:Array<EzsigntemplateelementdependencyResponseCompound> 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectTextstylestaticResponseCompound } from './'
// @ts-ignore
import { ValidationObjectTextstylestaticResponseCompound } from './'

/**
 * @export 
 * A EzsigntemplateformfieldResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateformfieldResponseCompound
 */
export class DataObjectEzsigntemplateformfieldResponseCompound {
    pkiEzsigntemplateformfieldID:number = 0
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
    eEzsigntemplateformfieldHorizontalalignment?:EnumHorizontalalignment = undefined
    objTextstylestatic?:TextstylestaticResponseCompound = undefined
    a_objEzsigntemplateelementdependency?:Array<EzsigntemplateelementdependencyResponseCompound> = undefined
}

/**
 * @export 
 * A EzsigntemplateformfieldResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplateformfieldResponseCompound
 */
export class ValidationObjectEzsigntemplateformfieldResponseCompound {
   pkiEzsigntemplateformfieldID = {
      type: 'integer',
      minimum: 0,
      required: true
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
      pattern: /^.{0,30}$/,
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
   eEzsigntemplateformfieldHorizontalalignment = {
      type: 'enum',
      allowableValues: ['Center','Left','Right'],
      required: false
   }
   objTextstylestatic = new ValidationObjectTextstylestaticResponseCompound()
   a_objEzsigntemplateelementdependency = {
      type: 'array',
      required: false
   }
} 


