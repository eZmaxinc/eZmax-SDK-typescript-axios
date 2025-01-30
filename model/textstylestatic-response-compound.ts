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
import type { TextstylestaticResponse } from './textstylestatic-response';

/**
 * @type TextstylestaticResponseCompound
 * A Textstylestatic Object
 * @export
 */
/*export type TextstylestaticResponseCompound = TextstylestaticResponse;*/
export interface TextstylestaticResponseCompound {
    /**
     * The unique ID of the Textstylestatic
     * @type {number}
     * @memberof TextstylestaticResponseCompound
     */
    pkiTextstylestaticID?:number 
    /**
     * The unique ID of the Font
     * @type {number}
     * @memberof TextstylestaticResponseCompound
     */
    fkiFontID:number 
    /**
     * The name of the Font
     * @type {string}
     * @memberof TextstylestaticResponseCompound
     */
    sFontName:string 
    /**
     * Whether the Textstylestatic is Bold or not
     * @type {boolean}
     * @memberof TextstylestaticResponseCompound
     */
    bTextstylestaticBold:boolean 
    /**
     * Whether the Textstylestatic is Underline or not
     * @type {boolean}
     * @memberof TextstylestaticResponseCompound
     */
    bTextstylestaticUnderline:boolean 
    /**
     * Whether the Textstylestatic is Italic or not
     * @type {boolean}
     * @memberof TextstylestaticResponseCompound
     */
    bTextstylestaticItalic:boolean 
    /**
     * Whether the Textstylestatic is Strikethrough or not
     * @type {boolean}
     * @memberof TextstylestaticResponseCompound
     */
    bTextstylestaticStrikethrough:boolean 
    /**
     * The int32 representation of the Fontcolor. For example, RGB color #39435B would be 3752795
     * @type {number}
     * @memberof TextstylestaticResponseCompound
     */
    iTextstylestaticFontcolor:number 
    /**
     * The Size for the Font of the Textstylestatic
     * @type {number}
     * @memberof TextstylestaticResponseCompound
     */
    iTextstylestaticSize:number 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A TextstylestaticResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectTextstylestaticResponseCompound
 */
export class DataObjectTextstylestaticResponseCompound {
    pkiTextstylestaticID?:number = undefined
    fkiFontID:number = 0
    sFontName:string = ''
    bTextstylestaticBold:boolean = false
    bTextstylestaticUnderline:boolean = false
    bTextstylestaticItalic:boolean = false
    bTextstylestaticStrikethrough:boolean = false
    iTextstylestaticFontcolor:number = 0
    iTextstylestaticSize:number = 0
}

/**
 * @export 
 * A TextstylestaticResponseCompound Validation Object
 * @class ValidationObjectTextstylestaticResponseCompound
 */
export class ValidationObjectTextstylestaticResponseCompound {
   pkiTextstylestaticID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiFontID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sFontName = {
      type: 'string',
      pattern: /^.{0,50}$/,
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


