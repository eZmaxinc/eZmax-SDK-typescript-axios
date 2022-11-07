/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignerResponseCompound } from './ezsigntemplatesigner-response-compound';

import { DefaultObject } from '../base'

/**
 * Payload for GET /2/object/ezsigntemplatesigner/{pkiEzsigntemplatesignerID}
 * @export
 * @interface EzsigntemplatesignerGetObjectV2ResponseMPayload
 */
export interface EzsigntemplatesignerGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsigntemplatesignerResponseCompound}
     * @memberof EzsigntemplatesignerGetObjectV2ResponseMPayload
     */
    'objEzsigntemplatesigner': EzsigntemplatesignerResponseCompound;
}
/**
 * A EzsigntemplatesignerGetObjectV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignerGetObjectV2ResponseMPayload
 */
export class DefaultObjectEzsigntemplatesignerGetObjectV2ResponseMPayload extends DefaultObject {
   objEzsigntemplatesigner:Partial<EzsigntemplatesignerResponseCompound> = {}
}


