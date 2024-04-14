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
import { EzsigntemplateelementdependencyResponse } from './ezsigntemplateelementdependency-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateelementdependencyOperator } from './field-eezsigntemplateelementdependency-operator';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateelementdependencyValidation } from './field-eezsigntemplateelementdependency-validation';

/**
 * @type EzsigntemplateelementdependencyResponseCompound
 * An Ezsigntemplateelementdependency Object and children to create a complete structure
 * @export
 */
/*export type EzsigntemplateelementdependencyResponseCompound = EzsigntemplateelementdependencyResponse;*/
export interface EzsigntemplateelementdependencyResponseCompound {
    /**
     * The unique ID of the Ezsigntemplateelementdependency
     * @type {number}
     * @memberof EzsigntemplateelementdependencyResponseCompound
     */
    pkiEzsigntemplateelementdependencyID:number 
    /**
     * The unique ID of the Ezsigntemplateformfield
     * @type {number}
     * @memberof EzsigntemplateelementdependencyResponseCompound
     */
    fkiEzsigntemplateformfieldID?:number 
    /**
     * The unique ID of the Ezsigntemplatesignature
     * @type {number}
     * @memberof EzsigntemplateelementdependencyResponseCompound
     */
    fkiEzsigntemplatesignatureID?:number 
    /**
     * The unique ID of the Ezsigntemplateformfield
     * @type {number}
     * @memberof EzsigntemplateelementdependencyResponseCompound
     */
    fkiEzsigntemplateformfieldIDValidation?:number 
    /**
     * The unique ID of the Ezsigntemplateformfieldgroup
     * @type {number}
     * @memberof EzsigntemplateelementdependencyResponseCompound
     */
    fkiEzsigntemplateformfieldgroupIDValidation?:number 
    /**
     * 
     * @type {FieldEEzsigntemplateelementdependencyValidation}
     * @memberof EzsigntemplateelementdependencyResponseCompound
     */
    eEzsigntemplateelementdependencyValidation:FieldEEzsigntemplateelementdependencyValidation 
    /**
     * Whether if it\'s selected or not when using eEzsigntemplateelementdependencyValidation = Selected
     * @type {boolean}
     * @memberof EzsigntemplateelementdependencyResponseCompound
     */
    bEzsigntemplateelementdependencySelected?:boolean 
    /**
     * 
     * @type {FieldEEzsigntemplateelementdependencyOperator}
     * @memberof EzsigntemplateelementdependencyResponseCompound
     */
    eEzsigntemplateelementdependencyOperator?:FieldEEzsigntemplateelementdependencyOperator 
    /**
     * The value of the Ezsignelementdependency
     * @type {string}
     * @memberof EzsigntemplateelementdependencyResponseCompound
     */
    sEzsigntemplateelementdependencyValue?:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateelementdependencyResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateelementdependencyResponseCompound
 */
export class DataObjectEzsigntemplateelementdependencyResponseCompound {
    pkiEzsigntemplateelementdependencyID:number = 0
    fkiEzsigntemplateformfieldID?:number = undefined
    fkiEzsigntemplatesignatureID?:number = undefined
    fkiEzsigntemplateformfieldIDValidation?:number = undefined
    fkiEzsigntemplateformfieldgroupIDValidation?:number = undefined
    eEzsigntemplateelementdependencyValidation:FieldEEzsigntemplateelementdependencyValidation = 'Value'
    bEzsigntemplateelementdependencySelected?:boolean = undefined
    eEzsigntemplateelementdependencyOperator?:FieldEEzsigntemplateelementdependencyOperator = undefined
    sEzsigntemplateelementdependencyValue?:string = undefined
}

/**
 * @export 
 * A EzsigntemplateelementdependencyResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplateelementdependencyResponseCompound
 */
export class ValidationObjectEzsigntemplateelementdependencyResponseCompound {
   pkiEzsigntemplateelementdependencyID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiEzsigntemplateformfieldID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplatesignatureID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplateformfieldIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplateformfieldgroupIDValidation = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   eEzsigntemplateelementdependencyValidation = {
      type: 'enum',
      allowableValues: ['Value','Selected','Filled'],
      required: true
   }
   bEzsigntemplateelementdependencySelected = {
      type: 'boolean',
      required: false
   }
   eEzsigntemplateelementdependencyOperator = {
      type: 'enum',
      allowableValues: ['eq','neq','gt','gte','lt','lte','in','nin','rg','like','between'],
      required: false
   }
   sEzsigntemplateelementdependencyValue = {
      type: 'string',
      pattern: '/^.{0,50}$/',
      required: false
   }
} 


