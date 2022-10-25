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
import { CustomEzmaxinvoicingEzsigndocumentResponse } from './custom-ezmaxinvoicing-ezsigndocument-response';
// May contain unused imports in some cases
// @ts-ignore
import { CustomEzmaxinvoicingEzsignfolderResponse } from './custom-ezmaxinvoicing-ezsignfolder-response';
// May contain unused imports in some cases
// @ts-ignore
import { CustomEzmaxpricingResponse } from './custom-ezmaxpricing-response';
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

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzmaxinvoicingResponseCompoundAllOf
 */
export interface EzmaxinvoicingResponseCompoundAllOf {
    /**
     * 
     * @type {EzmaxinvoicingcontractResponseCompound}
     * @memberof EzmaxinvoicingResponseCompoundAllOf
     */
    'objEzmaxinvoicingcontract': EzmaxinvoicingcontractResponseCompound;
    /**
     * 
     * @type {CustomEzmaxpricingResponse}
     * @memberof EzmaxinvoicingResponseCompoundAllOf
     */
    'objEzmaxpricing': CustomEzmaxpricingResponse;
    /**
     * 
     * @type {Array<EzmaxinvoicingsummaryglobalResponseCompound>}
     * @memberof EzmaxinvoicingResponseCompoundAllOf
     */
    'a_objEzmaxinvoicingsummaryglobal': Array<EzmaxinvoicingsummaryglobalResponseCompound>;
    /**
     * 
     * @type {Array<EzmaxinvoicingsummaryexternalResponseCompound>}
     * @memberof EzmaxinvoicingResponseCompoundAllOf
     */
    'a_objEzmaxinvoicingsummaryexternal': Array<EzmaxinvoicingsummaryexternalResponseCompound>;
    /**
     * 
     * @type {Array<EzmaxinvoicingsummaryinternalResponseCompound>}
     * @memberof EzmaxinvoicingResponseCompoundAllOf
     */
    'a_objEzmaxinvoicingsummaryinternal': Array<EzmaxinvoicingsummaryinternalResponseCompound>;
    /**
     * 
     * @type {Array<EzmaxinvoicingagentResponseCompound>}
     * @memberof EzmaxinvoicingResponseCompoundAllOf
     */
    'a_objEzmaxinvoicingagent': Array<EzmaxinvoicingagentResponseCompound>;
    /**
     * 
     * @type {Array<EzmaxinvoicinguserResponseCompound>}
     * @memberof EzmaxinvoicingResponseCompoundAllOf
     */
    'a_objEzmaxinvoicinguser': Array<EzmaxinvoicinguserResponseCompound>;
    /**
     * 
     * @type {Array<CustomEzmaxinvoicingEzsignfolderResponse>}
     * @memberof EzmaxinvoicingResponseCompoundAllOf
     */
    'a_objEzmaxinvoicingezsignfolder': Array<CustomEzmaxinvoicingEzsignfolderResponse>;
    /**
     * 
     * @type {Array<CustomEzmaxinvoicingEzsigndocumentResponse>}
     * @memberof EzmaxinvoicingResponseCompoundAllOf
     */
    'a_objEzmaxinvoicingezsigndocument': Array<CustomEzmaxinvoicingEzsigndocumentResponse>;
}
/**
 * A EzmaxinvoicingResponseCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzmaxinvoicingResponseCompoundAllOf
 */
export class DefaultObjectEzmaxinvoicingResponseCompoundAllOf extends DefaultObject {
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


