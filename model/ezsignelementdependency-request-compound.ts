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
import { EzsignelementdependencyRequest } from './ezsignelementdependency-request';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignelementdependencyOperator } from './field-eezsignelementdependency-operator';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignelementdependencyValidation } from './field-eezsignelementdependency-validation';

/**
 * @type EzsignelementdependencyRequestCompound
 * An Ezsignelementdependency Object and children to create a complete structure
 * @export
 */
/** export type EzsignelementdependencyRequestCompound = EzsignelementdependencyRequest; */
export interface EzsignelementdependencyRequestCompound {
    /**
     * The unique ID of the Ezsignelementdependency
     * @type {number}
     * @memberof EzsignelementdependencyRequestCompound
     */
    pkiEzsignelementdependencyID?:number 
    /**
     * The unique ID of the Ezsignformfield
     * @type {number}
     * @memberof EzsignelementdependencyRequestCompound
     */
    fkiEzsignformfieldIDValidation?:number 
    /**
     * The unique ID of the Ezsignformfieldgroup
     * @type {number}
     * @memberof EzsignelementdependencyRequestCompound
     */
    fkiEzsignformfieldgroupIDValidation?:number 
    /**
     * The Label for the Ezsignformfieldgroup
     * @type {string}
     * @memberof EzsignelementdependencyRequestCompound
     */
    sEzsignelementdependencyEzsignformfieldgrouplabel?:string 
    /**
     * The Label for the Ezsignformfield
     * @type {string}
     * @memberof EzsignelementdependencyRequestCompound
     */
    sEzsignelementdependencyEzsignformfieldlabel?:string 
    /**
     * 
     * @type {FieldEEzsignelementdependencyValidation}
     * @memberof EzsignelementdependencyRequestCompound
     */
    eEzsignelementdependencyValidation:FieldEEzsignelementdependencyValidation 
    /**
     * Whether if it\'s selected or not when using eEzsignelementdependencyValidation = Selected
     * @type {boolean}
     * @memberof EzsignelementdependencyRequestCompound
     */
    bEzsignelementdependencySelected?:boolean 
    /**
     * 
     * @type {FieldEEzsignelementdependencyOperator}
     * @memberof EzsignelementdependencyRequestCompound
     */
    eEzsignelementdependencyOperator?:FieldEEzsignelementdependencyOperator 
    /**
     * The value of the Ezsignelementdependency
     * @type {string}
     * @memberof EzsignelementdependencyRequestCompound
     */
    sEzsignelementdependencyValue?:string 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignelementdependencyRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignelementdependencyRequestCompound
 */
export class DataObjectEzsignelementdependencyRequestCompound {
    pkiEzsignelementdependencyID?:number = undefined
    fkiEzsignformfieldIDValidation?:number = undefined
    fkiEzsignformfieldgroupIDValidation?:number = undefined
    sEzsignelementdependencyEzsignformfieldgrouplabel?:string = undefined
    sEzsignelementdependencyEzsignformfieldlabel?:string = undefined
    eEzsignelementdependencyValidation:FieldEEzsignelementdependencyValidation = 'Value'
    bEzsignelementdependencySelected?:boolean = undefined
    eEzsignelementdependencyOperator?:FieldEEzsignelementdependencyOperator = undefined
    sEzsignelementdependencyValue?:string = undefined
}

/**
 * @export 
 * A EzsignelementdependencyRequestCompound Validation Object
 * @class ValidationObjectEzsignelementdependencyRequestCompound
 */
export class ValidationObjectEzsignelementdependencyRequestCompound {
   pkiEzsignelementdependencyID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
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
   sEzsignelementdependencyEzsignformfieldgrouplabel = {
      type: 'string',
      required: false
   }
   sEzsignelementdependencyEzsignformfieldlabel = {
      type: 'string',
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
      pattern: '/^.{0,50}$/',
      required: false
   }
} 

