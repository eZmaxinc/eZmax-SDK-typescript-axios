/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzmaxinvoicingagentVariationezmax } from './field-eezmaxinvoicingagent-variationezmax';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzmaxinvoicingagentVariationezsign } from './field-eezmaxinvoicingagent-variationezsign';

import { DefaultObject } from '../base'

/**
 * A Ezmaxinvoicingagent Object
 * @export
 * @interface EzmaxinvoicingagentResponse
 */
export interface EzmaxinvoicingagentResponse {
    /**
     * The unique ID of the Ezmaxinvoicingagent
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'pkiEzmaxinvoicingagentID'?: number;
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'fkiEzmaxinvoicingID'?: number;
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'fkiBillingentityinternalID': number;
    /**
     * The description of the Billingentityinternal in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingagentResponse
     */
    'sBillingentityinternalDescriptionX': string;
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'fkiAgentID'?: number;
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'fkiBrokerID'?: number;
    /**
     * The number of sessions
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'iEzmaxinvoicingagentSession': number;
    /**
     * The number of times this user was cloned
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'iEzmaxinvoicingagentCloned': number;
    /**
     * The number of invoices
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'iEzmaxinvoicingagentInvoice': number;
    /**
     * The number of inscriptions
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'iEzmaxinvoicingagentInscription': number;
    /**
     * The number of active inscriptions
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'iEzmaxinvoicingagentInscriptionactive': number;
    /**
     * The number of sales
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'iEzmaxinvoicingagentSale': number;
    /**
     * The number of otherincomes
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'iEzmaxinvoicingagentOtherincome': number;
    /**
     * The number of commission calculations
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'iEzmaxinvoicingagentCommissioncalculation': number;
    /**
     * The number of ezsign documents
     * @type {number}
     * @memberof EzmaxinvoicingagentResponse
     */
    'iEzmaxinvoicingagentEzsigndocument': number;
    /**
     * Whether the agent has an eZsign account
     * @type {boolean}
     * @memberof EzmaxinvoicingagentResponse
     */
    'bEzmaxinvoicingagentEzsignaccount': boolean;
    /**
     * Whether it is billable for eZmax
     * @type {boolean}
     * @memberof EzmaxinvoicingagentResponse
     */
    'bEzmaxinvoicingagentBillableezmax': boolean;
    /**
     * 
     * @type {FieldEEzmaxinvoicingagentVariationezmax}
     * @memberof EzmaxinvoicingagentResponse
     */
    'eEzmaxinvoicingagentVariationezmax': FieldEEzmaxinvoicingagentVariationezmax;
    /**
     * Whether it is billable for eZsign
     * @type {boolean}
     * @memberof EzmaxinvoicingagentResponse
     */
    'bEzmaxinvoicingagentBillableezsign': boolean;
    /**
     * 
     * @type {FieldEEzmaxinvoicingagentVariationezsign}
     * @memberof EzmaxinvoicingagentResponse
     */
    'eEzmaxinvoicingagentVariationezsign': FieldEEzmaxinvoicingagentVariationezsign;
}
/**
 * A EzmaxinvoicingagentResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzmaxinvoicingagentResponse
 */
export class DefaultObjectEzmaxinvoicingagentResponse extends DefaultObject {
   pkiEzmaxinvoicingagentID?:number = undefined
   fkiEzmaxinvoicingID?:number = undefined
   fkiBillingentityinternalID:number = 0
   sBillingentityinternalDescriptionX:string = ''
   fkiAgentID?:number = undefined
   fkiBrokerID?:number = undefined
   iEzmaxinvoicingagentSession:number = 0
   iEzmaxinvoicingagentCloned:number = 0
   iEzmaxinvoicingagentInvoice:number = 0
   iEzmaxinvoicingagentInscription:number = 0
   iEzmaxinvoicingagentInscriptionactive:number = 0
   iEzmaxinvoicingagentSale:number = 0
   iEzmaxinvoicingagentOtherincome:number = 0
   iEzmaxinvoicingagentCommissioncalculation:number = 0
   iEzmaxinvoicingagentEzsigndocument:number = 0
   bEzmaxinvoicingagentEzsignaccount:boolean = false
   bEzmaxinvoicingagentBillableezmax:boolean = false
   eEzmaxinvoicingagentVariationezmax:FieldEEzmaxinvoicingagentVariationezmax = 'Charge'
   bEzmaxinvoicingagentBillableezsign:boolean = false
   eEzmaxinvoicingagentVariationezsign:FieldEEzmaxinvoicingagentVariationezsign = 'Charge'
}

