/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomContactNameResponse } from './custom-contact-name-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingagentResponse } from './ezmaxinvoicingagent-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingagentResponseCompoundAllOf } from './ezmaxinvoicingagent-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzmaxinvoicingagentVariationezmax } from './field-eezmaxinvoicingagent-variationezmax';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzmaxinvoicingagentVariationezsign } from './field-eezmaxinvoicingagent-variationezsign';

import { DefaultObject } from '../base'

/**
 * @type EzmaxinvoicingagentResponseCompound
 * A Ezmaxinvoicingagent Object
 * @export
 */
export type EzmaxinvoicingagentResponseCompound = EzmaxinvoicingagentResponse & EzmaxinvoicingagentResponseCompoundAllOf;


/**
 * @export 
 * A EzmaxinvoicingagentResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzmaxinvoicingagentResponseCompound
 */
export class DefaultObjectEzmaxinvoicingagentResponseCompound extends DefaultObject {
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
   objContactName:Partial<CustomContactNameResponse> = {}
}


