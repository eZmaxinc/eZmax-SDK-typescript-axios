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
import type { EnumHorizontalalignment } from './enum-horizontalalignment';
// May contain unused imports in some cases
// @ts-ignore
import type { EnumVerticalalignment } from './enum-verticalalignment';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignannotationRequest } from './ezsignannotation-request';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsignannotationType } from './field-eezsignannotation-type';
// May contain unused imports in some cases
// @ts-ignore
import type { TextstylestaticRequestCompound } from './textstylestatic-request-compound';

/**
 * @type EzsignannotationRequestCompound
 * A Ezsignannotation Object and children
 * @export
 */
/*export type EzsignannotationRequestCompound = EzsignannotationRequest;*/
export interface EzsignannotationRequestCompound {
    /**
     * The unique ID of the Ezsignannotation
     * @type {number}
     * @memberof EzsignannotationRequestCompound
     */
    pkiEzsignannotationID?:number 
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignannotationRequestCompound
     */
    fkiEzsigndocumentID:number 
    /**
     * 
     * @type {EnumHorizontalalignment}
     * @memberof EzsignannotationRequestCompound
     */
    eEzsignannotationHorizontalalignment?:EnumHorizontalalignment 
    /**
     * 
     * @type {EnumVerticalalignment}
     * @memberof EzsignannotationRequestCompound
     */
    eEzsignannotationVerticalalignment?:EnumVerticalalignment 
    /**
     * 
     * @type {FieldEEzsignannotationType}
     * @memberof EzsignannotationRequestCompound
     */
    eEzsignannotationType:FieldEEzsignannotationType 
    /**
     * The X coordinate (Horizontal) where to put the Ezsignannotation on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignannotation 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignannotationRequestCompound
     */
    iEzsignannotationX:number 
    /**
     * The Y coordinate (Vertical) where to put the Ezsignannotation on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignannotation 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignannotationRequestCompound
     */
    iEzsignannotationY:number 
    /**
     * The Width of the Ezsignannotation.  Width is calculated at 100dpi (dot per inch). So for example, if you want to have the width of the Ezsignannotation to be 3 inches, you would use \"300\" for the Width.
     * @type {number}
     * @memberof EzsignannotationRequestCompound
     */
    iEzsignannotationWidth?:number 
    /**
     * The Height of the Ezsignannotation.  Height is calculated at 100dpi (dot per inch). So for example, if you want to have the height of the Ezsignannotation to be 2 inches, you would use \"200\" for the Height.  This can only be set if eEzsignannotationType is **StrikethroughBlock** or **Text**
     * @type {number}
     * @memberof EzsignannotationRequestCompound
     */
    iEzsignannotationHeight?:number 
    /**
     * The Text of the Ezsignannotation
     * @type {string}
     * @memberof EzsignannotationRequestCompound
     */
    sEzsignannotationText?:string 
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignannotationRequestCompound
     */
    iEzsignpagePagenumber:number 
    /**
     * 
     * @type {TextstylestaticRequestCompound}
     * @memberof EzsignannotationRequestCompound
     */
    objTextstylestatic?:TextstylestaticRequestCompound 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectTextstylestaticRequestCompound } from './'
// @ts-ignore
import { ValidationObjectTextstylestaticRequestCompound } from './'

/**
 * @export 
 * A EzsignannotationRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignannotationRequestCompound
 */
export class DataObjectEzsignannotationRequestCompound {
    pkiEzsignannotationID?:number = undefined
    fkiEzsigndocumentID:number = 0
    eEzsignannotationHorizontalalignment?:EnumHorizontalalignment = undefined
    eEzsignannotationVerticalalignment?:EnumVerticalalignment = undefined
    eEzsignannotationType:FieldEEzsignannotationType = 'StrikethroughBlock'
    iEzsignannotationX:number = 0
    iEzsignannotationY:number = 0
    iEzsignannotationWidth?:number = undefined
    iEzsignannotationHeight?:number = undefined
    sEzsignannotationText?:string = undefined
    iEzsignpagePagenumber:number = 0
    objTextstylestatic?:TextstylestaticRequestCompound = undefined
}

/**
 * @export 
 * A EzsignannotationRequestCompound Validation Object
 * @class ValidationObjectEzsignannotationRequestCompound
 */
export class ValidationObjectEzsignannotationRequestCompound {
   pkiEzsignannotationID = {
      type: 'integer',
      required: false
   }
   fkiEzsigndocumentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   eEzsignannotationHorizontalalignment = {
      type: 'enum',
      allowableValues: ['Center','Left','Right'],
      required: false
   }
   eEzsignannotationVerticalalignment = {
      type: 'enum',
      allowableValues: ['Bottom','Middle','Top'],
      required: false
   }
   eEzsignannotationType = {
      type: 'enum',
      allowableValues: ['StrikethroughBlock','StrikethroughLine','Text'],
      required: true
   }
   iEzsignannotationX = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignannotationY = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzsignannotationWidth = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzsignannotationHeight = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sEzsignannotationText = {
      type: 'string',
      required: false
   }
   iEzsignpagePagenumber = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   objTextstylestatic = new ValidationObjectTextstylestaticRequestCompound()
} 


