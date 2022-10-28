/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
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
import { FieldEEzmaxinvoicingPaymenttype } from './field-eezmaxinvoicing-paymenttype';

import { DefaultObject } from '../base'

/**
 * A Ezmaxinvoicing Object
 * @export
 * @interface EzmaxinvoicingResponse
 */
export interface EzmaxinvoicingResponse {
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicingResponse
     */
    'pkiEzmaxinvoicingID'?: number;
    /**
     * The unique ID of the Ezmaxinvoicingcontract
     * @type {number}
     * @memberof EzmaxinvoicingResponse
     */
    'fkiEzmaxinvoicingcontractID': number;
    /**
     * The unique ID of the Ezmaxpricing
     * @type {number}
     * @memberof EzmaxinvoicingResponse
     */
    'fkiEzmaxpricingID': number;
    /**
     * The unique ID of the Systemconfigurationtype
     * @type {number}
     * @memberof EzmaxinvoicingResponse
     */
    'fkiSystemconfigurationtypeID': number;
    /**
     * The description of the Systemconfigurationtype in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingResponse
     */
    'sSystemconfigurationtypeDescriptionX': string;
    /**
     * The YYYYMM period of the Ezmaxinvoicing
     * @type {string}
     * @memberof EzmaxinvoicingResponse
     */
    'yyyymmEzmaxinvoicing': string;
    /**
     * The number of days invoiced
     * @type {number}
     * @memberof EzmaxinvoicingResponse
     */
    'iEzmaxinvoicingDays': number;
    /**
     * 
     * @type {FieldEEzmaxinvoicingPaymenttype}
     * @memberof EzmaxinvoicingResponse
     */
    'eEzmaxinvoicingPaymenttype': FieldEEzmaxinvoicingPaymenttype;
    /**
     * The percentage of rebate depending of the payment type
     * @type {string}
     * @memberof EzmaxinvoicingResponse
     */
    'dEzmaxinvoicingRebatepaymenttype': string;
    /**
     * The length of the contract in years
     * @type {number}
     * @memberof EzmaxinvoicingResponse
     */
    'iEzmaxinvoicingContractlength': number;
    /**
     * The percentage of rebate depending of the contract length
     * @type {string}
     * @memberof EzmaxinvoicingResponse
     */
    'dEzmaxinvoicingRebatecontractlength': string;
    /**
     * Whether the rebate for eZsign is for all agents
     * @type {boolean}
     * @memberof EzmaxinvoicingResponse
     */
    'bEzmaxinvoicingRebateEzsignallagents': boolean;
    /**
     * 
     * @type {CommonAudit}
     * @memberof EzmaxinvoicingResponse
     */
    'objAudit'?: CommonAudit;
}
/**
 * A EzmaxinvoicingResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzmaxinvoicingResponse
 */
export class DefaultObjectEzmaxinvoicingResponse extends DefaultObject {
   pkiEzmaxinvoicingID?:number = undefined
   fkiEzmaxinvoicingcontractID:number = 0
   fkiEzmaxpricingID:number = 0
   fkiSystemconfigurationtypeID:number = 0
   sSystemconfigurationtypeDescriptionX:string = ''
   yyyymmEzmaxinvoicing:string = ''
   iEzmaxinvoicingDays:number = 0
   eEzmaxinvoicingPaymenttype:FieldEEzmaxinvoicingPaymenttype = 'Cheque'
   dEzmaxinvoicingRebatepaymenttype:string = ''
   iEzmaxinvoicingContractlength:number = 0
   dEzmaxinvoicingRebatecontractlength:string = ''
   bEzmaxinvoicingRebateEzsignallagents:boolean = false
   objAudit?:Partial<CommonAudit> = undefined
}


