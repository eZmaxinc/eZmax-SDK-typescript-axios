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
import type { TextstylestaticRequest } from './textstylestatic-request';

/**
 * @type TextstylestaticRequestCompound
 * A Textstylestatic Object and children
 * @export
 */
/*export type TextstylestaticRequestCompound = TextstylestaticRequest;*/
export interface TextstylestaticRequestCompound {
    /**
     * The unique ID of the Font
     * @type {number}
     * @memberof TextstylestaticRequestCompound
     */
    fkiFontID:number 
    /**
     * Whether the Textstylestatic is Bold or not
     * @type {boolean}
     * @memberof TextstylestaticRequestCompound
     */
    bTextstylestaticBold:boolean 
    /**
     * Whether the Textstylestatic is Underline or not
     * @type {boolean}
     * @memberof TextstylestaticRequestCompound
     */
    bTextstylestaticUnderline:boolean 
    /**
     * Whether the Textstylestatic is Italic or not
     * @type {boolean}
     * @memberof TextstylestaticRequestCompound
     */
    bTextstylestaticItalic:boolean 
    /**
     * Whether the Textstylestatic is Strikethrough or not
     * @type {boolean}
     * @memberof TextstylestaticRequestCompound
     */
    bTextstylestaticStrikethrough:boolean 
    /**
     * The int32 representation of the Fontcolor. For example, RGB color #39435B would be 3752795
     * @type {number}
     * @memberof TextstylestaticRequestCompound
     */
    iTextstylestaticFontcolor:number 
    /**
     * The Size for the Font of the Textstylestatic
     * @type {number}
     * @memberof TextstylestaticRequestCompound
     */
    iTextstylestaticSize:number 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A TextstylestaticRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectTextstylestaticRequestCompound
 */
export class DataObjectTextstylestaticRequestCompound {
    fkiFontID:number = 0
    bTextstylestaticBold:boolean = false
    bTextstylestaticUnderline:boolean = false
    bTextstylestaticItalic:boolean = false
    bTextstylestaticStrikethrough:boolean = false
    iTextstylestaticFontcolor:number = 0
    iTextstylestaticSize:number = 0
}

/**
 * @export 
 * A TextstylestaticRequestCompound Validation Object
 * @class ValidationObjectTextstylestaticRequestCompound
 */
export class ValidationObjectTextstylestaticRequestCompound {
   fkiFontID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bTextstylestaticBold = {
      type: 'boolean',
      required: true
   }
   bTextstylestaticUnderline = {
      type: 'boolean',
      required: true
   }
   bTextstylestaticItalic = {
      type: 'boolean',
      required: true
   }
   bTextstylestaticStrikethrough = {
      type: 'boolean',
      required: true
   }
   iTextstylestaticFontcolor = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   iTextstylestaticSize = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
} 


