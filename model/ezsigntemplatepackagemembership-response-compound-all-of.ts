/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
import { EzsigntemplatepackagesignermembershipResponseCompound } from './ezsigntemplatepackagesignermembership-response-compound';

/**
 * 
 * @export
 * @interface EzsigntemplatepackagemembershipResponseCompoundAllOf
 */
export interface EzsigntemplatepackagemembershipResponseCompoundAllOf {
    /**
     * 
     * @type {EzsigntemplateResponseCompound}
     * @memberof EzsigntemplatepackagemembershipResponseCompoundAllOf
     */
    'objEzsigntemplate': EzsigntemplateResponseCompound;
    /**
     * 
     * @type {Array<EzsigntemplatepackagesignermembershipResponseCompound>}
     * @memberof EzsigntemplatepackagemembershipResponseCompoundAllOf
     */
    'a_objEzsigntemplatepackagesignermembership': Array<EzsigntemplatepackagesignermembershipResponseCompound>;
}

