/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
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

import { DefaultObject } from '../base'

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
    'pkiEzmaxinvoicingcontractID': number;
    /**
     * 
     * @type {FieldEEzmaxinvoicingcontractPaymenttype}
     * @memberof EzmaxinvoicingcontractResponse
     */
    'eEzmaxinvoicingcontractPaymenttype': FieldEEzmaxinvoicingcontractPaymenttype;
    /**
     * The length in years of the Ezmaxinvoicingcontract
     * @type {number}
     * @memberof EzmaxinvoicingcontractResponse
     */
    'iEzmaxinvoicingcontractLength': number;
    /**
     * The start date of the Ezmaxinvoicingcontract
     * @type {string}
     * @memberof EzmaxinvoicingcontractResponse
     */
    'dtEzmaxinvoicingcontractStart': string;
    /**
     * The end date of the Ezmaxinvoicingcontract
     * @type {string}
     * @memberof EzmaxinvoicingcontractResponse
     */
    'dtEzmaxinvoicingcontractEnd': string;
    /**
     * The price of the license
     * @type {string}
     * @memberof EzmaxinvoicingcontractResponse
     */
    'dEzmaxinvoicingcontractLicense': string;
    /**
     * The price for 121QA
     * @type {string}
     * @memberof EzmaxinvoicingcontractResponse
     */
    'dEzmaxinvoicingcontract121qa': string;
    /**
     * Whether eZsign is for all agents
     * @type {boolean}
     * @memberof EzmaxinvoicingcontractResponse
     */
    'bEzmaxinvoicingcontractEzsignallagents': boolean;
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzmaxinvoicingcontractResponse
     */
    'objAudit': CommonAudit;
}
/**
 * A EzmaxinvoicingcontractResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzmaxinvoicingcontractResponse
 */
export class DefaultObjectEzmaxinvoicingcontractResponse extends DefaultObject {
   pkiEzmaxinvoicingcontractID:number = 0
   eEzmaxinvoicingcontractPaymenttype:FieldEEzmaxinvoicingcontractPaymenttype = 'Cheque'
   iEzmaxinvoicingcontractLength:number = 0
   dtEzmaxinvoicingcontractStart:string = ''
   dtEzmaxinvoicingcontractEnd:string = ''
   dEzmaxinvoicingcontractLicense:string = ''
   dEzmaxinvoicingcontract121qa:string = ''
   bEzmaxinvoicingcontractEzsignallagents:boolean = false
   objAudit:Partial<CommonAudit> = {}
}


