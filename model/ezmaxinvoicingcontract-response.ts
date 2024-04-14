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
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzmaxinvoicingcontractPaymenttype } from './field-eezmaxinvoicingcontract-paymenttype';

/**
 * A Ezmaxinvoicingcontract Object
 * @export
 * @interface EzmaxinvoicingcontractResponse
 */
export interface EzmaxinvoicingcontractResponse {
    /**
     * The unique ID of the Ezmaxinvoicingcontract
     * @type {number}
     * @memberof EzmaxinvoicingcontractResponse
     */
    /*'pkiEzmaxinvoicingcontractID': number;*/
    'pkiEzmaxinvoicingcontractID': number;
    /**
     * 
     * @type {FieldEEzmaxinvoicingcontractPaymenttype}
     * @memberof EzmaxinvoicingcontractResponse
     */
    /*'eEzmaxinvoicingcontractPaymenttype': FieldEEzmaxinvoicingcontractPaymenttype;*/
    'eEzmaxinvoicingcontractPaymenttype': FieldEEzmaxinvoicingcontractPaymenttype;
    /**
     * The length in years of the Ezmaxinvoicingcontract
     * @type {number}
     * @memberof EzmaxinvoicingcontractResponse
     */
    /*'iEzmaxinvoicingcontractLength': number;*/
    'iEzmaxinvoicingcontractLength': number;
    /**
     * The start date of the Ezmaxinvoicingcontract
     * @type {string}
     * @memberof EzmaxinvoicingcontractResponse
     */
    /*'dtEzmaxinvoicingcontractStart': string;*/
    'dtEzmaxinvoicingcontractStart': string;
    /**
     * The end date of the Ezmaxinvoicingcontract
     * @type {string}
     * @memberof EzmaxinvoicingcontractResponse
     */
    /*'dtEzmaxinvoicingcontractEnd': string;*/
    'dtEzmaxinvoicingcontractEnd': string;
    /**
     * The price of the license
     * @type {string}
     * @memberof EzmaxinvoicingcontractResponse
     */
    /*'dEzmaxinvoicingcontractLicense': string;*/
    'dEzmaxinvoicingcontractLicense': string;
    /**
     * The price for 121QA
     * @type {string}
     * @memberof EzmaxinvoicingcontractResponse
     */
    /*'dEzmaxinvoicingcontract121qa': string;*/
    'dEzmaxinvoicingcontract121qa': string;
    /**
     * Whether eZsign is for all agents
     * @type {boolean}
     * @memberof EzmaxinvoicingcontractResponse
     */
    /*'bEzmaxinvoicingcontractEzsignallagents': boolean;*/
    'bEzmaxinvoicingcontractEzsignallagents': boolean;
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzmaxinvoicingcontractResponse
     */
    /*'objAudit': CommonAudit;*/
    'objAudit': CommonAudit;
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A EzmaxinvoicingcontractResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingcontractResponse
 */
export class DataObjectEzmaxinvoicingcontractResponse {
   pkiEzmaxinvoicingcontractID:number = 0
   eEzmaxinvoicingcontractPaymenttype:FieldEEzmaxinvoicingcontractPaymenttype = 'Cheque'
   iEzmaxinvoicingcontractLength:number = 0
   dtEzmaxinvoicingcontractStart:string = ''
   dtEzmaxinvoicingcontractEnd:string = ''
   dEzmaxinvoicingcontractLicense:string = ''
   dEzmaxinvoicingcontract121qa:string = ''
   bEzmaxinvoicingcontractEzsignallagents:boolean = false
   objAudit:CommonAudit = new DataObjectCommonAudit()
}

/**
 * @export 
 * A EzmaxinvoicingcontractResponse Validation Object
 * @class ValidationObjectEzmaxinvoicingcontractResponse
 */
export class ValidationObjectEzmaxinvoicingcontractResponse {
   pkiEzmaxinvoicingcontractID = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   eEzmaxinvoicingcontractPaymenttype = {
      type: 'enum',
      allowableValues: ['Cheque','CreditCard','DirectDebit'],
      required: true
   }
   iEzmaxinvoicingcontractLength = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   dtEzmaxinvoicingcontractStart = {
      type: 'string',
      required: true
   }
   dtEzmaxinvoicingcontractEnd = {
      type: 'string',
      required: true
   }
   dEzmaxinvoicingcontractLicense = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingcontract121qa = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   bEzmaxinvoicingcontractEzsignallagents = {
      type: 'boolean',
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
} 


