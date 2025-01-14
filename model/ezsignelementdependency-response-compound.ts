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
import { EzsignelementdependencyResponse } from './ezsignelementdependency-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignelementdependencyOperator } from './field-eezsignelementdependency-operator';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignelementdependencyValidation } from './field-eezsignelementdependency-validation';

/**
 * @type EzsignelementdependencyResponseCompound
 * An Ezsignelementdependency Object and children to create a complete structure
 * @export
 */
/*export type EzsignelementdependencyResponseCompound = EzsignelementdependencyResponse;*/
export interface EzsignelementdependencyResponseCompound {
    /**
     * The unique ID of the Ezsignelementdependency
     * @type {number}
     * @memberof EzsignelementdependencyResponseCompound
     */
    pkiEzsignelementdependencyID:number 
    /**
     * The unique ID of the Ezsignformfield
     * @type {number}
     * @memberof EzsignelementdependencyResponseCompound
     */
    fkiEzsignformfieldID?:number 
    /**
     * The unique ID of the Ezsignsignature
     * @type {number}
     * @memberof EzsignelementdependencyResponseCompound
     */
    fkiEzsignsignatureID?:number 
    /**
     * The unique ID of the Ezsignformfield
     * @type {number}
     * @memberof EzsignelementdependencyResponseCompound
     */
    fkiEzsignformfieldIDValidation?:number 
    /**
     * The unique ID of the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignelementdependencyResponseCompound
     */
    fkiEzsignformfieldgroupIDValidation?:number 
    /**
     * 
     * @type {FieldEEzsignelementdependencyValidation}
     * @memberof EzsignelementdependencyResponseCompound
     */
    eEzsignelementdependencyValidation:FieldEEzsignelementdependencyValidation 
    /**
     * Whether if it\'s selected or not when using eEzsignelementdependencyValidation = Selected
     * @type {boolean}
     * @memberof EzsignelementdependencyResponseCompound
     */
    bEzsignelementdependencySelected?:boolean 
    /**
     * 
     * @type {FieldEEzsignelementdependencyOperator}
     * @memberof EzsignelementdependencyResponseCompound
     */
    eEzsignelementdependencyOperator?:FieldEEzsignelementdependencyOperator 
    /**
     * The value of the Ezsignelementdependency
     * @type {string}
     * @memberof EzsignelementdependencyResponseCompound
     */
    sEzsignelementdependencyValue?:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignelementdependencyResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignelementdependencyResponseCompound
 */
export class DataObjectEzsignelementdependencyResponseCompound {
    pkiEzsignelementdependencyID:number = 0
    fkiEzsignformfieldID?:number = undefined
    fkiEzsignsignatureID?:number = undefined
    fkiEzsignformfieldIDValidation?:number = undefined
    fkiEzsignformfieldgroupIDValidation?:number = undefined
    eEzsignelementdependencyValidation:FieldEEzsignelementdependencyValidation = 'Value'
    bEzsignelementdependencySelected?:boolean = undefined
    eEzsignelementdependencyOperator?:FieldEEzsignelementdependencyOperator = undefined
    sEzsignelementdependencyValue?:string = undefined
}

/**
 * @export 
 * A EzsignelementdependencyResponseCompound Validation Object
 * @class ValidationObjectEzsignelementdependencyResponseCompound
 */
export class ValidationObjectEzsignelementdependencyResponseCompound {
   pkiEzsignelementdependencyID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   fkiEzsignformfieldID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignsignatureID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignformfieldIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignformfieldgroupIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   eEzsignelementdependencyValidation = {
      type: 'enum',
      allowableValues: ['Value','Selected','Filled'],
      required: true
   }
   bEzsignelementdependencySelected = {
      type: 'boolean',
      required: false
   }
   eEzsignelementdependencyOperator = {
      type: 'enum',
      allowableValues: ['eq','neq','gt','gte','lt','lte','in','nin','rg','like','between'],
      required: false
   }
   sEzsignelementdependencyValue = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
} 


