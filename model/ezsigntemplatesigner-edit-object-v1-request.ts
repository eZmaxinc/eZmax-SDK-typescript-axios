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
import { EzsigntemplatesignerRequestCompound } from './ezsigntemplatesigner-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for PUT /1/object/ezsigntemplatesigner/{pkiEzsigntemplatesignerID}
 * @export
 * @interface EzsigntemplatesignerEditObjectV1Request
 */
export interface EzsigntemplatesignerEditObjectV1Request {
    /**
     * 
     * @type {EzsigntemplatesignerRequestCompound}
     * @memberof EzsigntemplatesignerEditObjectV1Request
     */
    'objEzsigntemplatesigner': EzsigntemplatesignerRequestCompound;
}
/**
 * A EzsigntemplatesignerEditObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatesignerEditObjectV1Request
 */
export class DefaultObjectEzsigntemplatesignerEditObjectV1Request extends DefaultObject {
   objEzsigntemplatesigner:Partial<EzsigntemplatesignerRequestCompound> = {}
}


