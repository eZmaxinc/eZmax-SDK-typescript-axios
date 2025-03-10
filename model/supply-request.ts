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
import type { MultilingualSupplyDescription } from './multilingual-supply-description';

/**
 * A Supply Object
 * @export
 * @interface SupplyRequest
 */
export interface SupplyRequest {
    /**
     * The unique ID of the Supply
     * @type {number}
     * @memberof SupplyRequest
     */
    /*'pkiSupplyID'?: number;*/
    'pkiSupplyID'?: number;
    /**
     * The unique ID of the Glaccount
     * @type {number}
     * @memberof SupplyRequest
     */
    /*'fkiGlaccountID'?: number;*/
    'fkiGlaccountID'?: number;
    /**
     * The unique ID of the Glaccountcontainer
     * @type {number}
     * @memberof SupplyRequest
     */
    /*'fkiGlaccountcontainerID'?: number;*/
    'fkiGlaccountcontainerID'?: number;
    /**
     * The unique ID of the Variableexpense
     * @type {number}
     * @memberof SupplyRequest
     */
    /*'fkiVariableexpenseID': number;*/
    'fkiVariableexpenseID': number;
    /**
     * The code of the Supply
     * @type {string}
     * @memberof SupplyRequest
     */
    /*'sSupplyCode': string;*/
    'sSupplyCode': string;
    /**
     * 
     * @type {MultilingualSupplyDescription}
     * @memberof SupplyRequest
     */
    /*'objSupplyDescription': MultilingualSupplyDescription;*/
    'objSupplyDescription': MultilingualSupplyDescription;
    /**
     * The unit price of the Supply
     * @type {string}
     * @memberof SupplyRequest
     */
    /*'dSupplyUnitprice': string;*/
    'dSupplyUnitprice': string;
    /**
     * Whether the supply is active or not
     * @type {boolean}
     * @memberof SupplyRequest
     */
    /*'bSupplyIsactive': boolean;*/
    'bSupplyIsactive': boolean;
    /**
     * Whether if the price is variable
     * @type {boolean}
     * @memberof SupplyRequest
     */
    /*'bSupplyVariableprice': boolean;*/
    'bSupplyVariableprice': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualSupplyDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualSupplyDescription } from './'

/**
 * @export 
 * A SupplyRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSupplyRequest
 */
export class DataObjectSupplyRequest {
   pkiSupplyID?:number = undefined
   fkiGlaccountID?:number = undefined
   fkiGlaccountcontainerID?:number = undefined
   fkiVariableexpenseID:number = 0
   sSupplyCode:string = ''
   objSupplyDescription:MultilingualSupplyDescription = new DataObjectMultilingualSupplyDescription()
   dSupplyUnitprice:string = ''
   bSupplyIsactive:boolean = false
   bSupplyVariableprice:boolean = false
}

/**
 * @export 
 * A SupplyRequest Validation Object
 * @class ValidationObjectSupplyRequest
 */
export class ValidationObjectSupplyRequest {
   pkiSupplyID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiGlaccountID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiGlaccountcontainerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiVariableexpenseID = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
   sSupplyCode = {
      type: 'string',
      pattern: /^.{0,5}$/,
      required: true
   }
   objSupplyDescription = new ValidationObjectMultilingualSupplyDescription()
   dSupplyUnitprice = {
      type: 'string',
      pattern: /^-{0,1}[\d]{1,9}?\.[\d]{2}$/,
      minLength: 4,
      maxLength: 13,
      required: true
   }
   bSupplyIsactive = {
      type: 'boolean',
      required: true
   }
   bSupplyVariableprice = {
      type: 'boolean',
      required: true
   }
} 


