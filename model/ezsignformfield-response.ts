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
import { FieldEEzsignformfieldDependencyrequirement } from './field-eezsignformfield-dependencyrequirement';
// May contain unused imports in some cases
// @ts-ignore
import { TextstylestaticResponseCompound } from './textstylestatic-response-compound';

/**
 * An Ezsignformfield Object
 * @export
 * @interface EzsignformfieldResponse
 */
export interface EzsignformfieldResponse {
    /**
     * The unique ID of the Ezsignformfield
     * @type {number}
     * @memberof EzsignformfieldResponse
     */
    /*'pkiEzsignformfieldID': number;*/
    'pkiEzsignformfieldID': number;
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignformfieldResponse
     */
    /*'iEzsignpagePagenumber': number;*/
    'iEzsignpagePagenumber': number;
    /**
     * The Label for the Ezsignformfield
     * @type {string}
     * @memberof EzsignformfieldResponse
     */
    /*'sEzsignformfieldLabel': string;*/
    'sEzsignformfieldLabel': string;
    /**
     * The value for the Ezsignformfield  This can only be set if eEzsignformfieldgroupType is Checkbox or Radio
     * @type {string}
     * @memberof EzsignformfieldResponse
     */
    /*'sEzsignformfieldValue'?: string;*/
    'sEzsignformfieldValue'?: string;
    /**
     * The X coordinate (Horizontal) where to put the Ezsignformfield on the Ezsignpage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignformfield 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignformfieldResponse
     */
    /*'iEzsignformfieldX': number;*/
    'iEzsignformfieldX': number;
    /**
     * The Y coordinate (Vertical) where to put the Ezsignformfield on the Ezsignpage.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignformfield 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignformfieldResponse
     */
    /*'iEzsignformfieldY': number;*/
    'iEzsignformfieldY': number;
    /**
     * The Width of the Ezsignformfield in pixels calculated at 100 DPI
     * @type {number}
     * @memberof EzsignformfieldResponse
     */
    /*'iEzsignformfieldWidth': number;*/
    'iEzsignformfieldWidth': number;
    /**
     * The Height of the Ezsignformfield in pixels calculated at 100 DPI 
     * @type {number}
     * @memberof EzsignformfieldResponse
     */
    /*'iEzsignformfieldHeight': number;*/
    'iEzsignformfieldHeight': number;
    /**
     * Whether the Ezsignformfield allows the use of the autocomplete of the browser.  This can only be set if eEzsignformfieldgroupType is **Text**
     * @type {boolean}
     * @memberof EzsignformfieldResponse
     */
    /*'bEzsignformfieldAutocomplete'?: boolean;*/
    'bEzsignformfieldAutocomplete'?: boolean;
    /**
     * Whether the Ezsignformfield is selected or not by default.  This can only be set if eEzsignformfieldgroupType is **Checkbox** or **Radio**
     * @type {boolean}
     * @memberof EzsignformfieldResponse
     */
    /*'bEzsignformfieldSelected'?: boolean;*/
    'bEzsignformfieldSelected'?: boolean;
    /**
     * This is the value enterred for the Ezsignformfield  This can only be set if eEzsignformfieldgroupType is **Dropdown**, **Text** or **Textarea**
     * @type {string}
     * @memberof EzsignformfieldResponse
     */
    /*'sEzsignformfieldEnteredvalue'?: string;*/
    'sEzsignformfieldEnteredvalue'?: string;
    /**
     * 
     * @type {FieldEEzsignformfieldDependencyrequirement}
     * @memberof EzsignformfieldResponse
     */
    /*'eEzsignformfieldDependencyrequirement'?: FieldEEzsignformfieldDependencyrequirement;*/
    'eEzsignformfieldDependencyrequirement'?: FieldEEzsignformfieldDependencyrequirement;
    /**
     * 
     * @type {EnumHorizontalalignment}
     * @memberof EzsignformfieldResponse
     */
    /*'eEzsignformfieldHorizontalalignment'?: EnumHorizontalalignment;*/
    'eEzsignformfieldHorizontalalignment'?: EnumHorizontalalignment;
    /**
     * 
     * @type {TextstylestaticResponseCompound}
     * @memberof EzsignformfieldResponse
     */
    /*'objTextstylestatic'?: TextstylestaticResponseCompound;*/
    'objTextstylestatic'?: TextstylestaticResponseCompound;
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
 * A EzsignformfieldResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignformfieldResponse
 */
export class DataObjectEzsignformfieldResponse {
   pkiEzsignformfieldID:number = 0
   iEzsignpagePagenumber:number = 0
   sEzsignformfieldLabel:string = ''
   sEzsignformfieldValue?:string = undefined
   iEzsignformfieldX:number = 0
   iEzsignformfieldY:number = 0
   iEzsignformfieldWidth:number = 0
   iEzsignformfieldHeight:number = 0
   bEzsignformfieldAutocomplete?:boolean = undefined
   bEzsignformfieldSelected?:boolean = undefined
   sEzsignformfieldEnteredvalue?:string = undefined
   eEzsignformfieldDependencyrequirement?:FieldEEzsignformfieldDependencyrequirement = undefined
   eEzsignformfieldHorizontalalignment?:EnumHorizontalalignment = undefined
   objTextstylestatic?:TextstylestaticResponseCompound = undefined
}

/**
 * @export 
 * A EzsignformfieldResponse Validation Object
 * @class ValidationObjectEzsignformfieldResponse
 */
export class ValidationObjectEzsignformfieldResponse {
   pkiEzsignformfieldID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   sEzsignformfieldLabel = {
      type: 'string',
      required: true
   }
   sEzsignformfieldValue = {
      type: 'string',
      required: false
   }
   iEzsignformfieldX = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignformfieldY = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignformfieldWidth = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignformfieldHeight = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzsignformfieldAutocomplete = {
      type: 'boolean',
      required: false
   }
   bEzsignformfieldSelected = {
      type: 'boolean',
      required: false
   }
   sEzsignformfieldEnteredvalue = {
      type: 'string',
      required: false
   }
   eEzsignformfieldDependencyrequirement = {
      type: 'enum',
      allowableValues: ['AllOf','AnyOf'],
      required: false
   }
   eEzsignformfieldHorizontalalignment = {
      type: 'enum',
      allowableValues: ['Center','Left','Right'],
      required: false
   }
   objTextstylestatic = new ValidationObjectTextstylestaticResponseCompound()
} 


