/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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
import { CustomEzmaxinvoicingEzsigndocumentResponse } from './custom-ezmaxinvoicing-ezsigndocument-response';
// May contain unused imports in some cases
// @ts-ignore
import { CustomEzmaxinvoicingEzsignfolderResponse } from './custom-ezmaxinvoicing-ezsignfolder-response';
// May contain unused imports in some cases
// @ts-ignore
import { CustomEzmaxpricingResponse } from './custom-ezmaxpricing-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingResponseCompound } from './ezmaxinvoicing-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingagentResponseCompound } from './ezmaxinvoicingagent-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingcontractResponseCompound } from './ezmaxinvoicingcontract-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingsummaryexternalResponseCompound } from './ezmaxinvoicingsummaryexternal-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingsummaryglobalResponseCompound } from './ezmaxinvoicingsummaryglobal-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingsummaryinternalResponseCompound } from './ezmaxinvoicingsummaryinternal-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicinguserResponseCompound } from './ezmaxinvoicinguser-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzmaxinvoicingPaymenttype } from './field-eezmaxinvoicing-paymenttype';

import { DefaultObject } from '../base'

/**
 * @type EzmaxinvoicingGetProvisionalV1ResponseMPayload
 * Payload for GET /1/object/ezmaxinvoicing/getProvisional
 * @export
 */
export type EzmaxinvoicingGetProvisionalV1ResponseMPayload = EzmaxinvoicingResponseCompound;


/**
 * @export 
 * A EzmaxinvoicingGetProvisionalV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzmaxinvoicingGetProvisionalV1ResponseMPayload
 */
export class DefaultObjectEzmaxinvoicingGetProvisionalV1ResponseMPayload extends DefaultObject {
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
   objEzmaxinvoicingcontract:Partial<EzmaxinvoicingcontractResponseCompound> = {}
   objEzmaxpricing:Partial<CustomEzmaxpricingResponse> = {}
   a_objEzmaxinvoicingsummaryglobal:Array<EzmaxinvoicingsummaryglobalResponseCompound> = []
   a_objEzmaxinvoicingsummaryexternal:Array<EzmaxinvoicingsummaryexternalResponseCompound> = []
   a_objEzmaxinvoicingsummaryinternal:Array<EzmaxinvoicingsummaryinternalResponseCompound> = []
   a_objEzmaxinvoicingagent:Array<EzmaxinvoicingagentResponseCompound> = []
   a_objEzmaxinvoicinguser:Array<EzmaxinvoicinguserResponseCompound> = []
   a_objEzmaxinvoicingezsignfolder:Array<CustomEzmaxinvoicingEzsignfolderResponse> = []
   a_objEzmaxinvoicingezsigndocument:Array<CustomEzmaxinvoicingEzsigndocumentResponse> = []
}


