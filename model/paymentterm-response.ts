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
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEPaymenttermType } from './field-epaymentterm-type';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualPaymenttermDescription } from './multilingual-paymentterm-description';

/**
 * A Paymentterm Object
 * @export
 * @interface PaymenttermResponse
 */
export interface PaymenttermResponse {
    /**
     * The unique ID of the Paymentterm
     * @type {number}
     * @memberof PaymenttermResponse
     */
    /*'pkiPaymenttermID': number;*/
    'pkiPaymenttermID': number;
    /**
     * The code of the Paymentterm
     * @type {string}
     * @memberof PaymenttermResponse
     */
    /*'sPaymenttermCode': string;*/
    'sPaymenttermCode': string;
    /**
     * 
     * @type {FieldEPaymenttermType}
     * @memberof PaymenttermResponse
     */
    /*'ePaymenttermType': FieldEPaymenttermType;*/
    'ePaymenttermType': FieldEPaymenttermType;
    /**
     * The day of the Paymentterm
     * @type {number}
     * @memberof PaymenttermResponse
     */
    /*'iPaymenttermDay': number;*/
    'iPaymenttermDay': number;
    /**
     * 
     * @type {MultilingualPaymenttermDescription}
     * @memberof PaymenttermResponse
     */
    /*'objPaymenttermDescription': MultilingualPaymenttermDescription;*/
    'objPaymenttermDescription': MultilingualPaymenttermDescription;
    /**
     * Whether the Paymentterm is active or not
     * @type {boolean}
     * @memberof PaymenttermResponse
     */
    /*'bPaymenttermIsactive': boolean;*/
    'bPaymenttermIsactive': boolean;
    /**
     * 
     * @type {CommonAudit}
     * @memberof PaymenttermResponse
     */
    /*'objAudit': CommonAudit;*/
    'objAudit': CommonAudit;
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualPaymenttermDescription } from './'
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectMultilingualPaymenttermDescription } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A PaymenttermResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermResponse
 */
export class DataObjectPaymenttermResponse {
   pkiPaymenttermID:number = 0
   sPaymenttermCode:string = ''
   ePaymenttermType:FieldEPaymenttermType = 'Days'
   iPaymenttermDay:number = 0
   objPaymenttermDescription:MultilingualPaymenttermDescription = new DataObjectMultilingualPaymenttermDescription()
   bPaymenttermIsactive:boolean = false
   objAudit:CommonAudit = new DataObjectCommonAudit()
}

/**
 * @export 
 * A PaymenttermResponse Validation Object
 * @class ValidationObjectPaymenttermResponse
 */
export class ValidationObjectPaymenttermResponse {
   pkiPaymenttermID = {
      type: 'integer',
      required: true
   }
   sPaymenttermCode = {
      type: 'string',
      pattern: '/^[A-Z0-9]{1,4}$/',
      required: true
   }
   ePaymenttermType = {
      type: 'enum',
      allowableValues: ['Days','Dayofthemonth'],
      required: true
   }
   iPaymenttermDay = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   objPaymenttermDescription = new ValidationObjectMultilingualPaymenttermDescription()
   bPaymenttermIsactive = {
      type: 'boolean',
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
} 


