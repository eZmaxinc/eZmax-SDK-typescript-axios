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
import { EnumHorizontalalignment } from './enum-horizontalalignment';
// May contain unused imports in some cases
// @ts-ignore
import { EnumVerticalalignment } from './enum-verticalalignment';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignannotationResponse } from './ezsignannotation-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignannotationType } from './field-eezsignannotation-type';
// May contain unused imports in some cases
// @ts-ignore
import { TextstylestaticResponseCompound } from './textstylestatic-response-compound';

/**
 * @type EzsignannotationResponseCompound
 * A Ezsignannotation Object
 * @export
 */
/*export type EzsignannotationResponseCompound = EzsignannotationResponse;*/
export interface EzsignannotationResponseCompound {
    /**
     * The unique ID of the Ezsignannotation
     * @type {number}
     * @memberof EzsignannotationResponseCompound
     */
    pkiEzsignannotationID:number 
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof EzsignannotationResponseCompound
     */
    fkiEzsigndocumentID:number 
    /**
     * 
     * @type {EnumHorizontalalignment}
     * @memberof EzsignannotationResponseCompound
     */
    eEzsignannotationHorizontalalignment?:EnumHorizontalalignment 
    /**
     * 
     * @type {EnumVerticalalignment}
     * @memberof EzsignannotationResponseCompound
     */
    eEzsignannotationVerticalalignment?:EnumVerticalalignment 
    /**
     * 
     * @type {FieldEEzsignannotationType}
     * @memberof EzsignannotationResponseCompound
     */
    eEzsignannotationType:FieldEEzsignannotationType 
    /**
     * The X coordinate (Horizontal) where to put the Ezsignannotation on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignannotation 2 inches from the left border of the page, you would use \"200\" for the X coordinate.
     * @type {number}
     * @memberof EzsignannotationResponseCompound
     */
    iEzsignannotationX:number 
    /**
     * The Y coordinate (Vertical) where to put the Ezsignannotation on the page.  Coordinate is calculated at 100dpi (dot per inch). So for example, if you want to put the Ezsignannotation 3 inches from the top border of the page, you would use \"300\" for the Y coordinate.
     * @type {number}
     * @memberof EzsignannotationResponseCompound
     */
    iEzsignannotationY:number 
    /**
     * The Width of the Ezsignannotation.  Width is calculated at 100dpi (dot per inch). So for example, if you want to have the width of the Ezsignannotation to be 3 inches, you would use \"300\" for the Width.
     * @type {number}
     * @memberof EzsignannotationResponseCompound
     */
    iEzsignannotationWidth?:number 
    /**
     * The Height of the Ezsignannotation.  Height is calculated at 100dpi (dot per inch). So for example, if you want to have the height of the Ezsignannotation to be 2 inches, you would use \"200\" for the Height.  This can only be set if eEzsignannotationType is **StrikethroughBlock** or **Text**
     * @type {number}
     * @memberof EzsignannotationResponseCompound
     */
    iEzsignannotationHeight?:number 
    /**
     * The Text of the Ezsignannotation
     * @type {string}
     * @memberof EzsignannotationResponseCompound
     */
    sEzsignannotationText?:string 
    /**
     * The page number in the Ezsigndocument
     * @type {number}
     * @memberof EzsignannotationResponseCompound
     */
    iEzsignpagePagenumber:number 
    /**
     * 
     * @type {TextstylestaticResponseCompound}
     * @memberof EzsignannotationResponseCompound
     */
    objTextstylestatic?:TextstylestaticResponseCompound 
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
 * A EzsignannotationResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignannotationResponseCompound
 */
export class DataObjectEzsignannotationResponseCompound {
    pkiEzsignannotationID:number = 0
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
    objTextstylestatic?:TextstylestaticResponseCompound = undefined
}

/**
 * @export 
 * A EzsignannotationResponseCompound Validation Object
 * @class ValidationObjectEzsignannotationResponseCompound
 */
export class ValidationObjectEzsignannotationResponseCompound {
   pkiEzsignannotationID = {
      type: 'integer',
      required: true
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
   objTextstylestatic = new ValidationObjectTextstylestaticResponseCompound()
} 


